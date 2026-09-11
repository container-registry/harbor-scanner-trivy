package scan_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"
	v1 "github.com/container-registry/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	storepkg "github.com/container-registry/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/container-registry/harbor-scanner-trivy/pkg/scan"
	"github.com/container-registry/harbor-scanner-trivy/pkg/trivy"
)

type resultWrapper struct{ run func() error }

func (w resultWrapper) Scan(trivy.ImageRef, trivy.ScanOption) (trivy.Report, error) {
	return trivy.Report{}, w.run()
}
func (resultWrapper) GetVersion() (trivy.VersionInfo, error) { return trivy.VersionInfo{}, nil }

func countMetric(t *testing.T, r *metrics.Recorder, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	var count float64
	for _, f := range families {
		if f.GetName() != metrics.Prefix+name {
			continue
		}
		for _, m := range f.Metric {
			matched := 0
			for _, l := range m.Label {
				if value, ok := labels[l.GetName()]; ok && value == l.GetValue() {
					matched++
				}
			}
			if matched != len(labels) {
				continue
			}
			if m.Counter != nil {
				count += m.Counter.GetValue()
			} else if m.Histogram != nil {
				count += float64(m.Histogram.GetSampleCount())
			} else if m.Gauge != nil {
				count += m.Gauge.GetValue()
			}
		}
	}
	return count
}

func TestMetricsTrackProcessingOutcomeNotStatusWriteOrPolling(t *testing.T) {
	for _, mode := range []string{"success", "scan_failure", "persistence_failure", "panic"} {
		t.Run(mode, func(t *testing.T) {
			server := miniredis.RunT(t)
			rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
			defer rdb.Close()
			r := metrics.New(true)
			r.RegisterRedis(rdb)
			store := storepkg.NewStore(etc.RedisStore{Namespace: "test", ScanJobTTL: time.Minute}, rdb, r)
			key := job.ScanJobKey{ID: "private-id", MIMEType: api.MimeTypeSecurityVulnerabilityReport}
			ctx := context.Background()
			require.NoError(t, store.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))
			before := countMetric(t, r, "store_bytes_written_total", map[string]string{"record": "job"})
			require.NoError(t, store.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))
			require.Equal(t, before, countMetric(t, r, "store_bytes_written_total", map[string]string{"record": "job"}), "duplicate Create must not count unapplied bytes")
			wrapper := resultWrapper{run: func() error {
				switch mode {
				case "scan_failure":
					return &trivy.ScanError{Category: trivy.ErrCategoryTimeout, Detail: "timeout"}
				case "persistence_failure":
					server.FlushAll()
				case "panic":
					panic("non-error panic")
				}
				return nil
			}}
			controller := scan.NewController(store, wrapper, scan.NewTransformer(&scan.SystemClock{}), r)
			req := &harbor.ScanRequest{Registry: harbor.Registry{URL: "https://registry.example"}, Artifact: harbor.Artifact{Repository: "project/image", Digest: "sha256:1234"}}
			err := controller.Scan(ctx, key, req)
			if mode == "persistence_failure" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			outcome := "failed"
			if mode == "success" {
				outcome = "success"
			}
			require.Equal(t, float64(1), countMetric(t, r, "job_attempts_total", map[string]string{"outcome": outcome}))
			require.Zero(t, countMetric(t, r, "jobs_in_progress", nil))
			if mode == "scan_failure" {
				require.Equal(t, float64(1), countMetric(t, r, "job_failures_total", map[string]string{"category": "timeout"}))
			}
			if mode == "success" {
				stored, err := store.Get(ctx, key)
				require.NoError(t, err)
				require.False(t, stored.FinishedAt.IsZero())
				require.Equal(t, float64(2), countMetric(t, r, "report_size_bytes", nil))
			} else {
				require.Zero(t, countMetric(t, r, "report_size_bytes", nil))
			}
			handler := v1.NewAPIHandler(etc.BuildInfo{}, etc.Config{API: etc.API{MetricsEnabled: true}}, nil, store, wrapper, r)
			for range 3 {
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/scan/private-id/report", nil))
				if mode == "success" {
					require.Equal(t, 200, res.Code)
				}
			}
			require.Equal(t, float64(1), countMetric(t, r, "job_attempts_total", nil), "polls must not count scans")
			require.Equal(t, float64(3), countMetric(t, r, "report_fetch_total", nil))
			if mode == "success" {
				require.Equal(t, float64(3), countMetric(t, r, "report_fetch_age_seconds", nil))
			}
			for i := 0; i < 10; i++ {
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, fmt.Sprintf("/missing/%d", i), nil))
			}
			require.Equal(t, float64(10), countMetric(t, r, "http_requests_total", map[string]string{"route": "unmatched"}))
			if mode == "success" {
				server.FastForward(2 * time.Minute)
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/scan/private-id/report", nil))
				require.Equal(t, 404, res.Code)
				require.Equal(t, float64(1), countMetric(t, r, "report_fetch_total", map[string]string{"result": "not_found"}))
			}
		})
	}
}
