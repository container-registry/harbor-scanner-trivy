package metrics

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
)

const bothDatabases = `{"Version":"0.74.0",
	"VulnerabilityDB":{"Version":2,"NextUpdate":"2026-09-16T10:00:00Z","UpdatedAt":"2026-09-15T10:00:00Z"},
	"JavaDB":{"Version":1,"NextUpdate":"2026-09-18T10:00:00Z","UpdatedAt":"2026-09-15T10:00:00Z"}}`

func probeConfig(interval time.Duration) etc.Config {
	return etc.Config{Metrics: etc.Metrics{CollectionInterval: interval, CollectionTimeout: time.Second}}
}

func fakeEngine(t *testing.T, output string, err error) *ext.MockAmbassador {
	t.Helper()
	ambassador := ext.NewMockAmbassador()
	ambassador.On("RunCmd", mock.Anything).Return([]byte(output), []byte{}, err)
	return ambassador
}

func TestEngineProbeReportsBothSchemaVersions(t *testing.T) {
	r := New(true)
	r.version.ttl = time.Minute
	version := r.probeEngine(context.Background(), probeConfig(time.Minute), fakeEngine(t, bothDatabases, nil), "adapter", "")
	require.Equal(t, "0.74.0", version)
	require.Equal(t, float64(2), testutil.ToFloat64(r.gauges["db_schema_version"].WithLabelValues("vulnerability")))
	require.Equal(t, float64(1), testutil.ToFloat64(r.gauges["db_schema_version"].WithLabelValues("java")))
	require.Equal(t, float64(1), testutil.ToFloat64(r.gauges["build_info"].WithLabelValues("adapter", "0.74.0")))
	cached, ok := r.CachedVersion()
	require.True(t, ok)
	require.JSONEq(t, bothDatabases, string(cached))
}

func TestNeverDownloadedJavaDatabaseHasNoSchemaVersion(t *testing.T) {
	r := New(true)
	output := `{"Version":"0.74.0","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-09-15T10:00:00Z"}}`
	require.Equal(t, "0.74.0", r.probeEngine(context.Background(), probeConfig(time.Minute), fakeEngine(t, output, nil), "adapter", ""))
	// The engine omits the block until the database exists, and a zero schema
	// version would read as a real one.
	require.Equal(t, 1, testutil.CollectAndCount(r.gauges["db_schema_version"]))
	require.Equal(t, float64(2), testutil.ToFloat64(r.gauges["db_schema_version"].WithLabelValues("vulnerability")))
}

func TestFailedEngineProbeInvalidatesSchemaVersionsAndSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output string
		err    error
	}{
		{"malformed json", "not json at all", nil},
		{"empty version", `{"VulnerabilityDB":{"Version":2}}`, nil},
		{"command failure", "", errors.New("exit status 1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(true)
			cfg := probeConfig(time.Minute)
			require.Equal(t, "0.74.0", r.probeEngine(context.Background(), cfg, fakeEngine(t, bothDatabases, nil), "adapter", ""))
			require.Empty(t, r.probeEngine(context.Background(), cfg, fakeEngine(t, tc.output, tc.err), "adapter", "0.74.0"))
			require.Zero(t, testutil.CollectAndCount(r.gauges["db_schema_version"]))
			// The binary has not changed, so the last known version stays visible.
			require.Equal(t, float64(1), testutil.ToFloat64(r.gauges["build_info"].WithLabelValues("adapter", "0.74.0")))
			r.collectMetadata(etc.Trivy{CacheDir: t.TempDir()}, false)
			require.Zero(t, testutil.ToFloat64(r.gauges["metadata_collection_success"]))
		})
	}
}

func TestUpgradedEngineReplacesItsBuildInfoSeries(t *testing.T) {
	r := New(true)
	cfg := probeConfig(time.Minute)
	require.Equal(t, "0.74.0", r.probeEngine(context.Background(), cfg, fakeEngine(t, bothDatabases, nil), "adapter", ""))
	upgraded := `{"Version":"0.75.0","VulnerabilityDB":{"Version":2}}`
	require.Equal(t, "0.75.0", r.probeEngine(context.Background(), cfg, fakeEngine(t, upgraded, nil), "adapter", "0.74.0"))
	require.Equal(t, 1, testutil.CollectAndCount(r.gauges["build_info"]))
	require.Equal(t, float64(1), testutil.ToFloat64(r.gauges["build_info"].WithLabelValues("adapter", "0.75.0")))
}

func TestCachedVersionExpiresWithTheCollectionInterval(t *testing.T) {
	r := New(true)
	r.version.ttl = 20 * time.Millisecond
	r.cacheVersion([]byte(bothDatabases))
	_, ok := r.CachedVersion()
	require.True(t, ok)
	time.Sleep(30 * time.Millisecond)
	_, ok = r.CachedVersion()
	require.False(t, ok)

	// A recorder that was never started has no interval, so nothing is current.
	fresh := New(true)
	fresh.cacheVersion([]byte(bothDatabases))
	_, ok = fresh.CachedVersion()
	require.False(t, ok)
	var disabled *Recorder
	_, ok = disabled.CachedVersion()
	require.False(t, ok)
}

func TestEveryTickProbesTheEngine(t *testing.T) {
	r := New(true)
	ambassador := ext.NewMockAmbassador()
	calls := make(chan struct{}, 8)
	ambassador.On("RunCmd", mock.Anything).Return([]byte(bothDatabases), []byte{}, nil).
		Run(func(mock.Arguments) {
			select {
			case calls <- struct{}{}:
			default:
			}
		})
	cfg := probeConfig(10 * time.Millisecond)
	cfg.Trivy.CacheDir = t.TempDir()
	cfg.Trivy.ReportsDir = t.TempDir()
	stop := r.Start(context.Background(), cfg, "adapter", ambassador)
	defer stop()
	for range 3 {
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatal("engine probe did not repeat")
		}
	}
}

func TestTempDirectoriesAreSizedSeparatelyFromTheCache(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"trivy-1", "trivy-2"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, name), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, name, "layer"), make([]byte, 1024), 0o600))
	}
	// Not Trivy's, and not counted.
	require.NoError(t, os.WriteFile(filepath.Join(root, "scan_report.json"), make([]byte, 4096), 0o600))

	budget := 100
	size, err := trivyTempBytes(context.Background(), root, &budget)
	require.NoError(t, err)
	require.EqualValues(t, 2048, size)

	// The walk shares the cache budget, so a flood of temp files cannot make
	// the sample run unbounded.
	exhausted := 1
	_, err = trivyTempBytes(context.Background(), root, &exhausted)
	require.ErrorContains(t, err, "budget exceeded")

	missing := 100
	_, err = trivyTempBytes(context.Background(), filepath.Join(root, "gone"), &missing)
	require.ErrorIs(t, err, fs.ErrNotExist)
}
