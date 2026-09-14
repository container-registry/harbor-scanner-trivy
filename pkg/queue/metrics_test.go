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
	_, err := NewEnqueuer(cfg, s).Enqueue(context.Background(), testRequest())
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
	id, err := NewEnqueuer(cfg, store).Enqueue(ctx, testRequest())
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
		require.NoError(t, store.Enqueue(context.Background(), job.ScanJob{Key: j.Key}, w.stream, []byte("fixture")))
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
	require.NoError(t, w.process(context.Background(), redis.XMessage{ID: "0-1", Values: map[string]interface{}{"job": "{}"}}))
	require.NoError(t, w.process(context.Background(), redis.XMessage{ID: "0-2", Values: map[string]interface{}{"job": "invalid JSON"}}))
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
	e := NewEnqueuer(etc.JobQueue{Namespace: "test"}, store, r)
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

func gaugeValue(t *testing.T, r *metrics.Recorder, name string) (float64, bool) {
	t.Helper()
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() == metrics.Prefix+name && len(f.Metric) > 0 {
			return f.Metric[0].GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func TestQueueMetricsRefreshWhileScanIsRunning(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	ctx := context.Background()
	r := metrics.New(true)
	started := make(chan struct{})
	w := NewWorker(cfg, rdb, scanFunc(func(ctx context.Context, _ job.ScanJobKey, _ *harbor.ScanRequest) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}), store, r)
	w.Start(ctx)
	t.Cleanup(w.Stop)
	_, err := NewEnqueuer(cfg, store).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not start")
	}
	_, err = NewEnqueuer(cfg, store).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		value, ok := gaugeValue(t, r, "queue_unacknowledged_jobs")
		return ok && value == 2
	}, 13*time.Second, 20*time.Millisecond)
	value, ok := gaugeValue(t, r, "queue_collection_last_success_timestamp_seconds")
	require.True(t, ok)
	require.InDelta(t, float64(time.Now().Unix()), value, 2)
}

func TestFailedQueueCollectionDropsStaleValues(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	r := metrics.New(true)
	w := NewWorker(cfg, rdb, &countingController{}, store, r).(*streamWorker)
	ctx := context.Background()
	w.observeQueue(ctx)
	last, ok := gaugeValue(t, r, "queue_collection_last_success_timestamp_seconds")
	require.True(t, ok)
	require.NoError(t, rdb.Close())
	w.observeQueue(ctx)
	status, _ := gaugeValue(t, r, "queue_collection_success")
	require.Zero(t, status)
	after, _ := gaugeValue(t, r, "queue_collection_last_success_timestamp_seconds")
	require.Equal(t, last, after)
	for _, name := range []string{"queue_unacknowledged_jobs", "queue_quarantined_jobs", "queue_oldest_age_seconds"} {
		_, ok := gaugeValue(t, r, name)
		require.False(t, ok, name)
	}
}

func TestDisabledMetricsDoNotReadRedis(t *testing.T) {
	worker := &streamWorker{} // No recorder or Redis client: any Redis read would panic.
	worker.monitorQueue(context.Background())
}
