package trivy

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
)

// How often temp_dirs_present is sampled. Sampling only counts; nothing is
// removed after startup.
const presentInterval = 10 * time.Minute

// Reaper removes what an adapter process that died left behind, and reports
// what the live one holds.
//
// The adapter gives each Trivy child a private TMPDIR under its own root and
// removes it after the child exits, so a child that is OOM-killed or otherwise
// SIGKILLed leaks nothing. Only an adapter that is itself killed cannot clean
// up, and its root outlives it on the pod's emptyDir until the container comes
// back. At that point every sibling root on the temp filesystem belongs to a
// process that is gone - one adapter runs per temp filesystem - so they are
// removed once, at startup, without inferring anything about their owners.
// There is no periodic sweep: after startup no new sibling can appear that
// this process should touch.
type Reaper struct {
	metrics *metrics.Recorder
	root    string
	own     *TempRoot
}

func NewReaper(own *TempRoot, recorders ...*metrics.Recorder) *Reaper {
	return &Reaper{metrics: metrics.Optional(recorders), root: os.TempDir(), own: own}
}

// Start removes the sibling roots left by previous processes, then samples the
// scratch directories under this process's own root until the context ends.
// The returned function waits for the sampler to stop.
func (r *Reaper) Start(ctx context.Context) func() {
	r.reapSiblings()
	// Sampled once here so the gauge is right when Start returns, not when the
	// goroutine happens to get scheduled.
	r.metrics.Set("temp_dirs_present", float64(childCount(r.own.Path())))
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(presentInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			r.metrics.Set("temp_dirs_present", float64(childCount(r.own.Path())))
		}
	}()
	return func() { cancel(); <-done }
}

func (r *Reaper) reapSiblings() {
	entries, err := os.ReadDir(r.root)
	if err != nil {
		slog.Warn("Listing the temp directory for roots of previous adapter processes failed",
			slog.String("path", r.root), slog.String("err", err.Error()))
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), AdapterTempPrefix) {
			continue
		}
		path := filepath.Join(r.root, entry.Name())
		if path == r.own.Path() {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			slog.Warn("Removing the temp root of a previous adapter process failed",
				slog.String("path", path), slog.String("err", err.Error()))
			continue
		}
		slog.Info("Removed the temp root of a previous adapter process", slog.String("path", path))
		r.metrics.Inc("temp_dirs_reaped_total")
	}
}

// childCount reports the scratch directories under this process's root, which
// is the scans in flight.
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
