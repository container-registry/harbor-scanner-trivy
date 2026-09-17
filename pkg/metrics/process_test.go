package metrics

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
)

func TestExpiredDeadlineIsNotReportedAsSignal(t *testing.T) {
	r := New(true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sleep", "30")
	cmd.WaitDelay = time.Second
	_, _, err := r.Run(ctx, "image", cmd, ext.DefaultAmbassador.RunCmd)
	require.Error(t, err)
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "timeout")))
	require.Zero(t, testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "signal")))
	// The adapter kills the child on its deadline, so the status is SIGKILL's;
	// the reason, not the code, says who did it.
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", "137")))
}

func TestExternalKillWithoutDeadlineIsASignal(t *testing.T) {
	r := New(true)
	cmd := exec.Command("sh", "-c", "kill -9 $$")
	_, _, err := r.Run(context.Background(), "image", cmd, ext.DefaultAmbassador.RunCmd)
	require.Error(t, err)
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "signal")))
	// The status a shell and a container runtime report, not Go's -1.
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", "137")))
}

func TestTerminationReportsTheConventionalStatus(t *testing.T) {
	r := New(true)
	cmd := exec.Command("sh", "-c", "kill -TERM $$")
	_, _, err := r.Run(context.Background(), "image", cmd, ext.DefaultAmbassador.RunCmd)
	require.Error(t, err)
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", "143")))
}

func TestCancellationIsNotAnExternalKill(t *testing.T) {
	r := New(true)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sleep", "30")
	cmd.WaitDelay = time.Second
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, _, err := r.Run(ctx, "image", cmd, ext.DefaultAmbassador.RunCmd)
	defer cancel()
	require.Error(t, err)
	// Shutdown and lease loss cancel the scan; neither is an OOM kill.
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "canceled")))
	require.Zero(t, testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "signal")))
	require.Zero(t, testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "timeout")))
}

func TestChildThatReportedItsOwnFailureKeepsThatReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"expired deadline", func() (context.Context, context.CancelFunc) {
			// A zero timeout is expired on creation; no sleep to race.
			ctx, cancel := context.WithTimeout(context.Background(), 0)
			return ctx, cancel
		}},
		{"canceled context", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(true)
			ctx, cancel := tc.ctx()
			defer cancel()
			// The child ran to completion and failed on its own terms, which is
			// what the operator has to act on, not the context that expired.
			cmd := exec.Command("sh", "-c", "exit 1")
			_, _, err := r.Run(ctx, "image", cmd, ext.DefaultAmbassador.RunCmd)
			require.Error(t, err)
			require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "nonzero_exit")))
			for _, reason := range []string{"timeout", "canceled", "signal"} {
				require.Zero(t, testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", reason)), reason)
			}
		})
	}
}

func TestExitStatusIsRecordedForEveryStartedChild(t *testing.T) {
	r := New(true)
	for _, code := range []string{"0", "1", "2", "9"} {
		cmd := exec.Command("sh", "-c", "exit "+code)
		_, _, err := r.Run(context.Background(), "image", cmd, ext.DefaultAmbassador.RunCmd)
		if code == "0" {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	for _, code := range []string{"0", "1", "2"} {
		require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", code)))
	}
	// 9 is outside the documented exit-status allowlist.
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", "other")))
	require.Equal(t, float64(3), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "nonzero_exit")))
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "success")))
}

func TestChildThatNeverStartsHasNoExitStatus(t *testing.T) {
	r := New(true)
	cmd := exec.Command(t.TempDir() + "/does-not-exist")
	_, _, err := r.Run(context.Background(), "image", cmd, ext.DefaultAmbassador.RunCmd)
	require.Error(t, err)
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "start_error")))
	require.Zero(t, testutil.CollectAndCount(r.counters["subprocess_exit_code_total"]))
}

func TestHTTPStatusLabelKeepsItsOwnDomain(t *testing.T) {
	r := New(true)
	r.Inc("http_requests_total", "/api/v1/metadata", "GET", "200")
	r.Inc("subprocess_exit_code_total", "image", "200")
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["http_requests_total"].WithLabelValues("/api/v1/metadata", "GET", "200")))
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", "other")))
}
