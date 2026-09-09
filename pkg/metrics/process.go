package metrics

import (
	"os/exec"
	"time"
)

// Run records a child attempt without changing its invocation or error behavior.
func (r *Recorder) Run(command string, cmd *exec.Cmd, run func(*exec.Cmd) ([]byte, error)) ([]byte, error) {
	if r == nil {
		return run(cmd)
	}
	started := time.Now()
	output, err := run(cmd)
	outcome, reason := "success", "success"
	if err != nil {
		outcome, reason = "failed", "nonzero_exit"
		if cmd.ProcessState == nil {
			reason = "start_error"
		} else if cmd.ProcessState.ExitCode() == -1 {
			reason = "signal"
		}
	}
	r.Observe("subprocess_duration_seconds", time.Since(started).Seconds(), command, outcome)
	r.Inc("subprocess_exits_total", command, reason)
	if rss, ok := maxRSS(cmd.ProcessState); ok {
		r.Observe("subprocess_max_rss_bytes", rss, command)
	}
	return output, err
}
