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
	_, _, err := r.Run(ctx, "image", cmd, func(cmd *exec.Cmd) ([]byte, []byte, error) { return ext.DefaultAmbassador.RunCmd(cmd) })
	require.Error(t, err)
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "timeout")))
	require.Zero(t, testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "signal")))
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", "other")))
}

func TestExternalKillWithoutDeadlineIsASignal(t *testing.T) {
	r := New(true)
	cmd := exec.Command("sh", "-c", "kill -9 $$")
	_, _, err := r.Run(context.Background(), "image", cmd, func(cmd *exec.Cmd) ([]byte, []byte, error) { return ext.DefaultAmbassador.RunCmd(cmd) })
	require.Error(t, err)
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "signal")))
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exit_code_total"].WithLabelValues("image", "other")))
}

func TestExitStatusIsRecordedForEveryStartedChild(t *testing.T) {
	r := New(true)
	for _, code := range []string{"0", "1", "2", "9"} {
		cmd := exec.Command("sh", "-c", "exit "+code)
		_, _, err := r.Run(context.Background(), "image", cmd, func(cmd *exec.Cmd) ([]byte, []byte, error) { return ext.DefaultAmbassador.RunCmd(cmd) })
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
	_, _, err := r.Run(context.Background(), "image", cmd, func(cmd *exec.Cmd) ([]byte, []byte, error) { return ext.DefaultAmbassador.RunCmd(cmd) })
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
