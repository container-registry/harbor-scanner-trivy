package trivy

import (
	"fmt"
	"os"
	"time"
)

// AdapterTempPrefix names the temp roots the adapter creates for its children.
//
// Trivy's own scratch directory is $TMPDIR/trivy-<random>: pkg/x/os.initTempDir
// calls os.MkdirTemp(os.TempDir(), "trivy-"), whose suffix is random precisely
// so that containers sharing a /tmp do not collide. The name therefore says
// nothing about which process owns the directory, and nothing outside that
// process can tell a running scan's layers from an abandoned child's. So the
// adapter creates the directory itself, points the child's TMPDIR at it, and
// removes it once the child is gone.
const AdapterTempPrefix = "harbor-scanner-trivy-"

// TempRoot is one adapter process's root for child scratch directories.
//
// The name is random rather than derived from the pid. The chart mounts /tmp as
// an emptyDir that outlives a container restart while the adapter comes back as
// pid 1, so a pid-derived name would hand a new process the dead one's root and
// its leaked children, which is the leak this exists to prevent.
//
// Liveness is published rather than guessed: the owner touches the root on a
// timer, so its age is evidence about the process and not about how long the
// current scan has been writing into a subdirectory. A root nothing refreshes
// belongs to an adapter that is gone, whatever its pid was and whichever pid
// namespace it was in.
type TempRoot struct {
	path string
}

func NewTempRoot() (*TempRoot, error) {
	path, err := os.MkdirTemp(os.TempDir(), AdapterTempPrefix)
	if err != nil {
		return nil, fmt.Errorf("creating the adapter temp root: %w", err)
	}
	return &TempRoot{path: path}, nil
}

func (t *TempRoot) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

// Heartbeat republishes this process's claim on the root. A failure is not worth
// reporting on its own: the sweep that reads it only removes a root after
// reapMinAge, so a missed touch costs nothing and a persistent one shows up as
// the root being reaped while idle.
func (t *TempRoot) Heartbeat() {
	if t == nil {
		return
	}
	now := time.Now()
	_ = os.Chtimes(t.path, now, now)
}

// Close removes the root on a clean shutdown, so the usual case leaves nothing
// for the next process to sweep.
func (t *TempRoot) Close() error {
	if t == nil {
		return nil
	}
	return os.RemoveAll(t.path)
}
