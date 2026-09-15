package trivy

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
)

const (
	reapInterval   = 10 * time.Minute
	tempDirPrefix  = "trivy-"
	reapMaxEntries = 100000
	// Pids are reused, so a directory younger than this may belong to a new
	// scan whose pid once belonged to a dead one. Waiting costs disk for one
	// interval; not waiting deletes a running scan's layers.
	reapMinAge = 10 * time.Minute
)

// Reaper removes the per-process temp directories that Trivy leaves behind.
// Trivy cleans up $TMPDIR/trivy-<pid> when it exits, but a child that is
// OOM-killed or otherwise SIGKILLed never gets to, so the extracted layers of
// the scan that killed it stay on the pod's temp filesystem until the pod is
// replaced. Reaping is independent of metrics collection: a disabled recorder
// only silences the counters.
type Reaper struct {
	metrics *metrics.Recorder
	root    string
	self    int
}

func NewReaper(recorders ...*metrics.Recorder) *Reaper {
	return &Reaper{metrics: metrics.Optional(recorders), root: os.TempDir(), self: os.Getpid()}
}

// Start sweeps immediately, because the directories worth reaping were left by
// a previous pod, and then on a fixed interval. The returned function waits for
// an in-flight sweep.
func (r *Reaper) Start(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(reapInterval)
		defer ticker.Stop()
		for {
			r.sweep()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (r *Reaper) sweep() {
	entries, err := os.ReadDir(r.root)
	if err != nil {
		slog.Warn("Listing the temp directory for abandoned Trivy directories failed",
			slog.String("path", r.root), slog.String("err", err.Error()))
		// A count from the last sweep would claim to describe this one.
		r.metrics.Delete("temp_dirs_present")
		return
	}
	present := 0
	for _, entry := range entries {
		pid, ok := tempDirPID(entry)
		if !ok {
			continue
		}
		present++
		// A live pid is scanning right now, and the adapter never owns one of
		// these: removing either would break a scan in progress.
		if pid == r.self || processAlive(pid) {
			continue
		}
		info, err := entry.Info()
		if err != nil || time.Since(info.ModTime()) < reapMinAge {
			continue
		}
		path := filepath.Join(r.root, entry.Name())
		freed := directorySize(path)
		// Between the check above and here a new scan can have taken the pid
		// and started writing into this directory, so ask once more.
		if processAlive(pid) {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			slog.Warn("Removing an abandoned Trivy temp directory failed",
				slog.String("path", path), slog.String("err", err.Error()))
			continue
		}
		present--
		slog.Info("Removed an abandoned Trivy temp directory",
			slog.String("path", path), slog.Int64("freed_bytes", freed))
		r.metrics.Inc("temp_dirs_reaped_total")
	}
	r.metrics.Set("temp_dirs_present", float64(present))
}

func tempDirPID(entry fs.DirEntry) (int, bool) {
	if !entry.IsDir() || !strings.HasPrefix(entry.Name(), tempDirPrefix) {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), tempDirPrefix))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// directorySize reports what the sweep is about to free. It is logging detail,
// so a partial walk is reported rather than failing the removal.
func directorySize(path string) int64 {
	var total int64
	visited := 0
	_ = filepath.WalkDir(path, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if visited++; visited > reapMaxEntries {
			return fs.SkipAll
		}
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}
