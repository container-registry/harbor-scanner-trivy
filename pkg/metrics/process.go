package metrics

import (
	"context"
	"errors"
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
		switch {
		case cmd.ProcessState == nil:
			reason = "start_error"
		// A cancelled context kills the child, and Wait then reports the signal
		// rather than the deadline. Only the context separates an expired
		// timeout from an external kill such as an OOM.
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			reason = "timeout"
		case cmd.ProcessState.ExitCode() == -1:
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
		r.Inc("subprocess_exit_code_total", command, strconv.Itoa(cmd.ProcessState.ExitCode()))
	}
	if rss, ok := maxRSS(cmd.ProcessState); ok {
		r.Observe("subprocess_max_rss_bytes", rss, command)
	}
	return stdout, stderr, err
}
