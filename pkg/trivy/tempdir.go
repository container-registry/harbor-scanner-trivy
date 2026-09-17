package trivy

import (
	"os"
	"path/filepath"
	"strconv"
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

// TempRoot is this process's root for child scratch directories. One adapter
// process runs per container, so a sibling root belongs to an adapter that is
// no longer running.
func TempRoot() string {
	return filepath.Join(os.TempDir(), AdapterTempPrefix+strconv.Itoa(os.Getpid()))
}
