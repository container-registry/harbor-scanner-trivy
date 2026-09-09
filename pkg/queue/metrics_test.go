package queue

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	storepkg "github.com/container-registry/harbor-scanner-trivy/pkg/persistence/redis"
)

type countingController struct{ count int }

func (c *countingController) Scan(context.Context, job.ScanJobKey, *harbor.ScanRequest) error {
	c.count++
	return nil
}

func metricCount(t *testing.T, r *metrics.Recorder, suffix, label, value string) float64 {
	t.Helper()
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	var count float64
	for _, f := range families {
		if f.GetName() != metrics.Prefix+suffix {
			continue
		}
		for _, m := range f.Metric {
			ok := label == ""
			for _, l := range m.Label {
				if l.GetName() == label && l.GetValue() == value {
					ok = true
				}
			}
			if ok {
				if m.Counter != nil {
					count += m.Counter.GetValue()
				}
				if m.Histogram != nil {
					count += float64(m.Histogram.GetSampleCount())
				}
			}
		}
	}
	return count
}

func TestDispatchCountsOnlyAcquiredLocksAndKnownWaits(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	defer rdb.Close()
	r := metrics.New(true)
	controller := &countingController{}
	w := NewWorker(etc.JobQueue{Namespace: "test", WorkerConcurrency: 1}, rdb, controller, r).(*worker)
	j := Job{Key: job.ScanJobKey{ID: "id", MIMEType: api.MimeTypeSecurityVulnerabilityReport}, Args: Args{ScanRequest: &harbor.ScanRequest{}}, EnqueuedAt: time.Now().Add(-time.Second)}
	run := func(j Job) {
		b, err := json.Marshal(j)
		require.NoError(t, err)
		require.NoError(t, w.scanArtifact(context.Background(), &redis.Message{Payload: string(b)}))
	}
	run(j)
	run(j)
	require.Equal(t, 1, controller.count)
	require.Equal(t, float64(1), metricCount(t, r, "job_dispatch_total", "result", "lock_busy"))
	require.Equal(t, float64(1), metricCount(t, r, "queue_wait_duration_seconds", "", ""))
	j.Key.ID = "old"
	j.EnqueuedAt = time.Time{}
	run(j)
	j.Key.ID = "future"
	j.EnqueuedAt = time.Now().Add(time.Hour)
	run(j)
	require.Equal(t, float64(1), metricCount(t, r, "queue_wait_duration_seconds", "", ""))
	require.Error(t, w.scanArtifact(context.Background(), &redis.Message{Payload: "{}"}))
	require.Error(t, w.scanArtifact(context.Background(), &redis.Message{Payload: "invalid JSON"}))
	require.Equal(t, float64(2), metricCount(t, r, "job_dispatch_total", "result", "decode_error"))
	s.Close()
	require.Error(t, w.scanArtifact(context.Background(), &redis.Message{Payload: `{"Args":{"ScanRequest":{}}}`}))
	require.Equal(t, float64(1), metricCount(t, r, "job_dispatch_total", "result", "lock_error"))
}

func TestEnqueueFanoutAndNoSubscribers(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	defer rdb.Close()
	r := metrics.New(true)
	store := storepkg.NewStore(etc.RedisStore{Namespace: "test", ScanJobTTL: time.Minute}, rdb, r)
	e := NewEnqueuer(etc.JobQueue{Namespace: "test"}, rdb, store, r)
	_, err := e.Enqueue(context.Background(), harbor.ScanRequest{Capabilities: []harbor.Capability{
		{Type: harbor.CapabilityTypeVulnerability, ProducesMIMETypes: []api.MIMEType{api.MimeTypeSecurityVulnerabilityReport}},
		{Type: harbor.CapabilityTypeSBOM, ProducesMIMETypes: []api.MIMEType{api.MimeTypeSecuritySBOMReport}, Parameters: &harbor.CapabilityAttributes{SBOMMediaTypes: []api.MediaType{api.MediaTypeSPDX, api.MediaTypeCycloneDX}}},
	}})
	require.NoError(t, err)
	require.Equal(t, float64(3), metricCount(t, r, "jobs_enqueued_total", "", ""))
	require.Equal(t, float64(3), metricCount(t, r, "publish_no_subscribers_total", "", ""))
	require.Zero(t, metricCount(t, r, "job_attempts_total", "", ""))
}
