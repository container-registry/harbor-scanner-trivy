package trivy

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
)

const (
	reapInterval   = 10 * time.Minute
	reapMaxEntries = 100000
	// The shared temp root holds every process's scratch space, so it is read in
	// chunks rather than loaded whole.
	reapBatch = 256
	// A root whose owner has not touched it for this long has no owner left. It
	// is several heartbeats, so a descheduled or briefly stalled adapter does
	// not lose the scan it is running.
	reapMinAge = 10 * time.Minute
	// Comfortably inside reapMinAge, and unrelated to the sweep interval: the
	// claim has to stay fresh whether or not this pod is sweeping.
	heartbeatInterval = 2 * time.Minute
)

// Reaper removes the child scratch directories left by adapter processes that
// died. The adapter gives each Trivy child a private TMPDIR under its own root
// and removes it after the child exits, so a child that is OOM-killed or
// otherwise SIGKILLed leaks nothing. An adapter that is itself killed cannot
// clean up, and its root is what this removes. Reaping is independent of
// metrics collection: a disabled recorder only silences the counters.
type Reaper struct {
	metrics *metrics.Recorder
	root    string
	own     *TempRoot
}

func NewReaper(own *TempRoot, recorders ...*metrics.Recorder) *Reaper {
	return &Reaper{metrics: metrics.Optional(recorders), root: os.TempDir(), own: own}
}

// Start publishes this process's claim on its own root, sweeps immediately
// because the roots worth reaping were left by a previous process, and then
// keeps both going. The returned function waits for an in-flight sweep.
func (r *Reaper) Start(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.own.Heartbeat()
		r.sweep(ctx)
		sweeps := time.NewTicker(reapInterval)
		defer sweeps.Stop()
		beats := time.NewTicker(heartbeatInterval)
		defer beats.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-beats.C:
				r.own.Heartbeat()
			case <-sweeps.C:
				r.own.Heartbeat()
				r.sweep(ctx)
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (r *Reaper) sweep(ctx context.Context) {
	dir, err := os.Open(r.root)
	if err != nil {
		slog.Warn("Listing the temp directory for abandoned adapter directories failed",
			slog.String("path", r.root), slog.String("err", err.Error()))
		// A count from the last sweep would claim to describe this one.
		r.metrics.Delete("temp_dirs_present")
		return
	}
	defer dir.Close()
	present := 0
	for {
		if ctx.Err() != nil {
			r.metrics.Delete("temp_dirs_present")
			return
		}
		entries, readErr := dir.ReadDir(reapBatch)
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), AdapterTempPrefix) {
				continue
			}
			present += r.consider(filepath.Join(r.root, entry.Name()), entry)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			slog.Warn("Reading the temp directory failed",
				slog.String("path", r.root), slog.String("err", readErr.Error()))
			r.metrics.Delete("temp_dirs_present")
			return
		}
	}
	r.metrics.Set("temp_dirs_present", float64(present))
}

// consider removes one adapter root if nothing owns it any more, and reports the
// child scratch directories left standing under it.
func (r *Reaper) consider(path string, entry fs.DirEntry) int {
	if path == r.own.Path() || !unowned(entry) {
		return childCount(path)
	}
	freed := directorySize(path)
	if err := os.RemoveAll(path); err != nil {
		slog.Warn("Removing an abandoned adapter temp directory failed",
			slog.String("path", path), slog.String("err", err.Error()))
		return childCount(path)
	}
	slog.Info("Removed the temp directory of an adapter process that is gone",
		slog.String("path", path), slog.Int64("freed_bytes", freed))
	r.metrics.Inc("temp_dirs_reaped_total")
	return 0
}

// unowned reports whether the root's owner has stopped refreshing it. The owner
// touches its own root every heartbeatInterval, so this measures the process
// rather than what the current scan happens to be writing. An unreadable entry
// is treated as owned: the cost of waiting one interval is disk, the cost of
// being wrong is a running scan.
func unowned(entry fs.DirEntry) bool {
	info, err := entry.Info()
	return err == nil && time.Since(info.ModTime()) >= reapMinAge
}

// childCount reports the scratch directories under an adapter root. Under this
// process's own root that is the scans in flight; under a root left behind it is
// what the sweep could not remove yet.
func childCount(root string) int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count
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
