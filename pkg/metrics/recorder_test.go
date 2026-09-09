package metrics

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
)

func TestExecutionAccountingAndCardinality(t *testing.T) {
	r := New(true)
	key := job.ScanJobKey{ID: "must-not-be-a-label", MIMEType: api.MimeTypeSecurityVulnerabilityReport}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); finish := r.BeginExecution(key); finish(i%2 == 0, "scan", "timeout") }()
	}
	wg.Wait()
	require.Equal(t, float64(10), testutil.ToFloat64(r.counters["job_attempts_total"].WithLabelValues("vulnerability", "json", "failed")))
	require.Equal(t, float64(10), testutil.ToFloat64(r.counters["job_attempts_total"].WithLabelValues("vulnerability", "json", "success")))
	require.Zero(t, testutil.ToFloat64(r.gauges["jobs_in_progress"].WithLabelValues()))
	require.Zero(t, r.oldest())
	for range 50 {
		r.Inc("http_requests_total", "/private/image/id", "CUSTOM", "99999")
	}
	require.Equal(t, float64(50), testutil.ToFloat64(r.counters["http_requests_total"].WithLabelValues("other", "other", "other")))
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	for _, family := range families {
		require.NotContains(t, family.String(), key.ID)
	}
	require.Nil(t, New(false))
	var disabled *Recorder
	disabled.Inc("not-even-registered")
	disabled.BeginExecution(key)(true, "", "")
}

func TestDatabasePresenceAndInvalidation(t *testing.T) {
	r := New(true)
	cfg := etc.Trivy{CacheDir: t.TempDir()}
	dir := filepath.Join(cfg.CacheDir, "db")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), []byte("fixture"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(`{"Version":2,"UpdatedAt":"2026-09-09T10:00:00Z","NextUpdate":"2026-09-09T16:00:00Z","DownloadedAt":"2026-09-09T11:00:00Z"}`), 0o600))
	r.collectMetadata(cfg, true)
	require.Equal(t, float64(1), testutil.ToFloat64(r.gauges["db_present"].WithLabelValues("vulnerability")))
	require.Zero(t, testutil.ToFloat64(r.gauges["db_present"].WithLabelValues("java")))
	require.Equal(t, 1, testutil.CollectAndCount(r.gauges["db_updated_timestamp_seconds"]))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(`{"Version":2}`), 0o600))
	r.collectMetadata(cfg, true)
	require.Zero(t, testutil.ToFloat64(r.gauges["metadata_collection_success"].WithLabelValues()))
	require.Zero(t, testutil.CollectAndCount(r.gauges["db_updated_timestamp_seconds"]))
	// A previously recorded last-success timestamp remains, exposing staleness.
	require.Equal(t, 1, testutil.CollectAndCount(r.gauges["metadata_last_success_timestamp_seconds"]))
}

func TestBoundedCacheCollection(t *testing.T) {
	r := New(true)
	root := t.TempDir()
	for _, dir := range []string{"fanal", "db", "java-db"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, dir), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(root, dir, "data"), []byte("12345"), 0o600))
	}
	r.collectCache(context.Background(), root, 20)
	require.Equal(t, float64(5), testutil.ToFloat64(r.gauges["cache_size_bytes"].WithLabelValues("analysis")))
	r.collectCache(context.Background(), root, 1)
	require.Zero(t, testutil.CollectAndCount(r.gauges["cache_size_bytes"]))
	require.Zero(t, testutil.ToFloat64(r.gauges["storage_collection_success"].WithLabelValues("cache_size")))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := 100
	_, err := directoryBytes(ctx, root, &n)
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, os.Symlink(root, filepath.Join(root, "fanal", "loop")))
	_, err = directoryBytes(context.Background(), root, &n)
	require.ErrorContains(t, err, "unsupported cache entry")
}

func TestSubprocessFailureAndUnavailableUsage(t *testing.T) {
	r := New(true)
	cmd := exec.Command(filepath.Join(t.TempDir(), "does-not-exist"))
	_, err := r.Run("image", cmd, func(cmd *exec.Cmd) ([]byte, error) { return cmd.CombinedOutput() })
	require.Error(t, err)
	require.Equal(t, float64(1), testutil.ToFloat64(r.counters["subprocess_exits_total"].WithLabelValues("image", "start_error")))
	require.Zero(t, testutil.CollectAndCount(r.histograms["subprocess_max_rss_bytes"]))
}

func TestCollectorShutdownAndOutputLimit(t *testing.T) {
	var buffer limitedBuffer
	_, err := buffer.Write([]byte(strings.Repeat("x", (1<<20)+1)))
	require.Error(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := etc.Config{Metrics: etc.Metrics{CollectionInterval: time.Minute, CollectionTimeout: time.Second}}
	r := New(true)
	r.Start(ctx, cfg, "test")()
	require.Zero(t, testutil.CollectAndCount(r.gauges["metadata_last_success_timestamp_seconds"]))
	New(false).Start(context.Background(), cfg, "test")()
}
