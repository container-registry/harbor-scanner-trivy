package queue

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	"github.com/stretchr/testify/require"
)

func TestRecreationFailureIsLoggedOnTransitions(t *testing.T) {
	mr, rdb, store, cfg := setupQueue(t)
	w := NewWorker(cfg, rdb, &countingController{}, store, metrics.New(true)).(*streamWorker)
	requireGroup(t, w)
	ctx := context.Background()
	require.NoError(t, rdb.XGroupDestroy(ctx, w.stream, workerGroup).Err())

	var logs bytes.Buffer
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	failed := func() int { return strings.Count(logs.String(), "Recreating the scan consumer group failed") }

	// The backend refuses every command, as a read-only replica or a primary
	// with a failed RDB save does, so recreation fails on each retry. The read
	// loop retries once a second; the log must not.
	cause := errors.New("NOGROUP No such key or consumer group")
	mr.SetError("MISCONF Redis is configured to save RDB snapshots")
	for i := 0; i < 5; i++ {
		require.True(t, w.recoverMissingGroup(ctx, cause))
	}
	require.Equal(t, 1, failed(), logs.String())

	// A different refusal is news; the same one again is not.
	mr.SetError("READONLY You can't write against a read only replica.")
	for i := 0; i < 3; i++ {
		require.True(t, w.recoverMissingGroup(ctx, cause))
	}
	require.Equal(t, 2, failed(), logs.String())

	// Once the backend accepts writes again the recovery is reported once, and
	// the usual recreation line follows.
	mr.SetError("")
	require.True(t, w.recoverMissingGroup(ctx, cause))
	require.Equal(t, 1, strings.Count(logs.String(), "succeeded after earlier failures"), logs.String())
	require.Equal(t, 1, strings.Count(logs.String(), "Recreated the scan consumer group"), logs.String())

	// Quiet from here: BUSYGROUP on the next read is neither a failure nor a
	// recovery to report.
	require.True(t, w.recoverMissingGroup(ctx, cause))
	require.Equal(t, 2, failed())
	require.Equal(t, 1, strings.Count(logs.String(), "succeeded after earlier failures"))
}
