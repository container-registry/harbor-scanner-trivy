package metrics

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Run records a child attempt without changing its invocation or error behavior.
func (r *Recorder) Run(ctx context.Context, command string, cmd *exec.Cmd, run func(*exec.Cmd) ([]byte, []byte, error)) ([]byte, []byte, error) {
	if r == nil {
		return run(cmd)
	}
	started := time.Now()
	stdout, stderr, err := run(cmd)
	outcome, reason := "success", "success"
	if err != nil {
		outcome = "failed"
		// The context kills the child, so Wait reports a signal either way and
		// only the context says who ended it. A child that reached its own exit
		// status reported a real failure, whatever the context did afterwards.
		killed := cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == -1
		switch {
		case cmd.ProcessState == nil:
			reason = "start_error"
		case killed && errors.Is(ctx.Err(), context.Canceled):
			reason = "canceled"
		case killed && errors.Is(ctx.Err(), context.DeadlineExceeded):
			reason = "timeout"
		case killed:
			reason = "signal"
		case cmd.ProcessState.ExitCode() != 0:
			reason = "nonzero_exit"
		default:
			reason = "other"
		}
	}
	r.Observe("subprocess_duration_seconds", time.Since(started).Seconds(), command, outcome)
	r.Inc("subprocess_exits_total", command, reason)
	if cmd.ProcessState != nil {
		r.Inc("subprocess_exit_code_total", command, exitStatus(cmd.ProcessState))
	}
	if rss, ok := maxRSS(cmd.ProcessState); ok {
		r.Observe("subprocess_max_rss_bytes", rss, command)
	}
	return stdout, stderr, err
}

func exitStatus(state *os.ProcessState) string {
	if code, ok := signalExitCode(state); ok {
		return strconv.Itoa(code)
	}
	return strconv.Itoa(state.ExitCode())
}
