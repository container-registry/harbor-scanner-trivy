//go:build linux || darwin

package trivy

import (
	"errors"
	"syscall"
)

// processAlive reports whether a process holds the pid. A permission error
// proves it does: the process exists but belongs to another user.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
