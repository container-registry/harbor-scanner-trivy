//go:build !linux && !darwin

package trivy

// Without a way to ask whether a pid is alive, treat every one as alive:
// leaving a directory behind costs disk, removing a live scan's costs the scan.
func processAlive(int) bool { return true }
