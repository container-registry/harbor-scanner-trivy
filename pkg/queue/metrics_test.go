package queue

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence"
	storepkg "github.com/container-registry/harbor-scanner-trivy/pkg/persistence/redis"
)

type countingController struct{ count int }

func TestDurableEnqueueHasItsOwnStoreOperation(t *testing.T) {
	_, rdb, _, cfg := setupQueue(t)
	r := metrics.New(true)
	s := storepkg.NewStore(etc.RedisStore{Namespace: "enqueue-metrics"}, rdb, r)
	_, err := NewEnqueuer(cfg, rdb, s).Enqueue(context.Background(), testRequest())
	require.NoError(t, err)
	require.EqualValues(t, 1, metricCount(t, r, "store_operations_total", "operation", "enqueue"))
	require.Zero(t, metricCount(t, r, "store_operations_total", "operation", "create"))
}

type slowReadStore struct {
	persistence.Store
	readDuration time.Duration
}

func (s *slowReadStore) Get(ctx context.Context, key job.ScanJobKey) (*job.ScanJob, error) {
	start := time.Now()
	time.Sleep(200 * time.Millisecond)
	state, err := s.Store.Get(ctx, key)
	s.readDuration = time.Since(start)
	return state, err
}

func TestQueueWaitExcludesMetadataRead(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	ctx := context.Background()
	id, err := NewEnqueuer(cfg, rdb, store).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	r := metrics.New(true)
	slow := &slowReadStore{Store: store}
	w := NewWorker(cfg, rdb, &countingController{}, slow, r).(*streamWorker)
	delivery := Job{Key: job.ScanJobKey{ID: id, MIMEType: api.MimeTypeSecurityVulnerabilityReport}, Args: Args{ScanRequest: &harbor.ScanRequest{}}, EnqueuedAt: time.Now()}
	payload, err := json.Marshal(delivery)
	require.NoError(t, err)
	require.ErrorContains(t, w.process(ctx, redis.XMessage{ID: "test", Values: map[string]interface{}{"job": string(payload)}}), "interrupted scan")
	elapsed := time.Since(delivery.EnqueuedAt)
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() == metrics.Prefix+"queue_wait_duration_seconds" {
			h := f.Metric[0].GetHistogram()
			require.EqualValues(t, 1, h.GetSampleCount())
			require.Less(t, h.GetSampleSum(), (elapsed - slow.readDuration + 50*time.Millisecond).Seconds())
			return
		}
	}
	t.Fatal("queue wait was not observed")
}

func (c *countingController) Scan(context.Context, job.ScanJobKey, *harbor.ScanRequest) error {
	c.count++
	return errors.New("interrupted scan")
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
	store := storepkg.NewStore(etc.RedisStore{Namespace: "test", ScanJobTTL: time.Minute}, rdb, r)
	w := NewWorker(etc.JobQueue{Namespace: "test", WorkerConcurrency: 1}, rdb, controller, store, r).(*streamWorker)
	j := Job{Key: job.ScanJobKey{ID: "id", MIMEType: api.MimeTypeSecurityVulnerabilityReport}, Args: Args{ScanRequest: &harbor.ScanRequest{}}, EnqueuedAt: time.Now().Add(-time.Second)}
	run := func(j Job) {
		require.NoError(t, store.Create(context.Background(), job.ScanJob{Key: j.Key}))
		b, err := json.Marshal(j)
		require.NoError(t, err)
		require.ErrorContains(t, w.process(context.Background(), redis.XMessage{ID: j.Key.ID, Values: map[string]interface{}{"job": string(b)}}), "interrupted scan")
	}
	run(j)
	b, err := json.Marshal(j)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(context.Background(), w.stream+":lease:id", "another-worker", time.Minute).Err())
	require.NoError(t, w.process(context.Background(), redis.XMessage{ID: "id", Values: map[string]interface{}{"job": string(b)}}))
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
	require.NoError(t, w.process(context.Background(), redis.XMessage{Values: map[string]interface{}{"job": "{}"}}))
	require.NoError(t, w.process(context.Background(), redis.XMessage{Values: map[string]interface{}{"job": "invalid JSON"}}))
	require.Equal(t, float64(2), metricCount(t, r, "job_dispatch_total", "result", "decode_error"))
	s.Close()
	require.Error(t, w.process(context.Background(), redis.XMessage{Values: map[string]interface{}{"job": `{"Args":{"ScanRequest":{}}}`}}))
	require.Equal(t, float64(1), metricCount(t, r, "job_dispatch_total", "result", "lock_error"))
}

func TestEnqueueFanoutWithoutOnlineWorkers(t *testing.T) {
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
	require.EqualValues(t, 3, rdb.XLen(context.Background(), redisJobStream("test")).Val())
	require.Zero(t, metricCount(t, r, "publish_no_subscribers_total", "", ""))
	require.Zero(t, metricCount(t, r, "job_attempts_total", "", ""))
}
