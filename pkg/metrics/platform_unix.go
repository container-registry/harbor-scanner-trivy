//go:build linux || darwin

package metrics

import (
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// signalExitCode reports the conventional 128+signal status of a child that was
// killed, which is what a shell and a container runtime report. Go's ExitCode
// returns -1 for every signal, losing SIGKILL (137) and SIGTERM (143).
func signalExitCode(state *os.ProcessState) (int, bool) {
	if state == nil {
		return 0, false
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return 0, false
	}
	return 128 + int(status.Signal()), true
}

func maxRSS(state *os.ProcessState) (float64, bool) {
	if state == nil {
		return 0, false
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage.Maxrss <= 0 {
		return 0, false
	}
	n := float64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		n *= 1024
	}
	return n, true
}

func filesystem(path string) (capacity, available, inodes float64, err error) {
	var stat unix.Statfs_t
	if err = unix.Statfs(path, &stat); err != nil {
		return
	}
	capacity = float64(stat.Blocks) * float64(stat.Bsize)
	available = float64(stat.Bavail) * float64(stat.Bsize)
	inodes = -1
	if stat.Files > 0 {
		inodes = float64(stat.Ffree)
	}
	return
}
