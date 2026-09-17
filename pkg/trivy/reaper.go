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
	// A sibling root belongs to an adapter that is gone, because one adapter
	// runs per container. The age guard only covers a second adapter that
	// started moments ago in a development environment sharing one /tmp.
	reapMinAge = 10 * time.Minute
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
	own     string
}

func NewReaper(recorders ...*metrics.Recorder) *Reaper {
	return &Reaper{metrics: metrics.Optional(recorders), root: os.TempDir(), own: TempRoot()}
}

// Start sweeps immediately, because the roots worth reaping were left by a
// previous pod, and then on a fixed interval. The returned function waits for
// an in-flight sweep.
func (r *Reaper) Start(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(reapInterval)
		defer ticker.Stop()
		for {
			r.sweep(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
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
			path := filepath.Join(r.root, entry.Name())
			if path == r.own {
				present += childCount(path)
				continue
			}
			info, err := entry.Info()
			if err != nil || time.Since(info.ModTime()) < reapMinAge {
				present += childCount(path)
				continue
			}
			freed := directorySize(path)
			if err := os.RemoveAll(path); err != nil {
				slog.Warn("Removing an abandoned adapter temp directory failed",
					slog.String("path", path), slog.String("err", err.Error()))
				present += childCount(path)
				continue
			}
			slog.Info("Removed the temp directory of an adapter process that is gone",
				slog.String("path", path), slog.Int64("freed_bytes", freed))
			r.metrics.Inc("temp_dirs_reaped_total")
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
