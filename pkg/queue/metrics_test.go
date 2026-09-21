package queue

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
	requireGroup(t, w)
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

func requireGroup(t *testing.T, w *streamWorker) {
	t.Helper()
	_, err := w.ensureGroup(context.Background())
	require.NoError(t, err)
}

func TestQueueOutageIsCountedPerQueryAndLoggedOnceOnEachTransition(t *testing.T) {
	server, rdb, store, cfg := setupQueue(t)
	r := metrics.New(true)
	w := NewWorker(cfg, rdb, &countingController{}, store, r).(*streamWorker)
	ctx := context.Background()
	requireGroup(t, w)
	var logged []string
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				logged = append(logged, a.Value.String())
			}
			return a
		},
	})))

	w.observeQueue(ctx)
	require.Empty(t, logged)
	for _, query := range []string{"quarantine", "length", "oldest", "group"} {
		require.Zero(t, metricCount(t, r, "queue_collection_errors_total", "query", query), query)
	}

	server.SetError("redis outage")
	for range 3 {
		w.observeQueue(ctx)
	}
	for _, query := range []string{"quarantine", "length", "oldest", "group"} {
		require.Equal(t, float64(3), metricCount(t, r, "queue_collection_errors_total", "query", query), query)
	}
	require.Equal(t, []string{"Queue metric collection failed"}, logged)

	server.SetError("")
	w.observeQueue(ctx)
	w.observeQueue(ctx)
	require.Equal(t, []string{"Queue metric collection failed", "Queue metric collection recovered"}, logged)
	status, _ := gaugeValue(t, r, "queue_collection_success")
	require.Equal(t, float64(1), status)
}

func TestLostConsumerGroupIsRecreatedAndCounted(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	r := metrics.New(true)
	ctx := context.Background()
	scanned := make(chan struct{}, 1)
	w := NewWorker(cfg, rdb, scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		select {
		case scanned <- struct{}{}:
		default:
		}
		return store.UpdateStatus(ctx, key, job.Finished)
	}), store, r).(*streamWorker)
	// A job backend without persistence comes back with no consumer group, and
	// the group the worker created at startup is gone. Redis answers NOGROUP
	// for a missing group and for a missing stream key alike.
	requireGroup(t, w)
	require.NoError(t, rdb.XGroupDestroy(ctx, w.stream, workerGroup).Err())

	// Sampled with no worker running, so nothing can repair the group first.
	w.observeQueue(ctx)
	status, _ := gaugeValue(t, r, "queue_collection_success")
	require.Zero(t, status, "a queue nothing can read from is not healthy")
	require.Equal(t, float64(1), metricCount(t, r, "queue_collection_errors_total", "query", "group"))

	w.Start(ctx)
	t.Cleanup(w.Stop)
	// The loop recreates the group at startup like any restart would, so take
	// it away again to reach the state the loop itself has to recover from.
	require.Eventually(t, func() bool {
		groups, err := rdb.XInfoGroups(ctx, w.stream).Result()
		return err == nil && len(groups) == 1
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, rdb.XGroupDestroy(ctx, w.stream, workerGroup).Err())

	_, err := NewEnqueuer(cfg, store).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	select {
	case <-scanned:
	case <-time.After(15 * time.Second):
		t.Fatal("no delivery was dispatched after the consumer group was lost")
	}
	// One recreation per loss, not one per replica that noticed it.
	require.Equal(t, float64(1), metricCount(t, r, "queue_group_recreated_total", "", ""))

	// Sample only once the loop has stopped: observeQueue is the monitor
	// goroutine's, and calling it from the test alongside a running worker is a
	// data race, not a scenario the adapter has.
	w.Stop()
	w.observeQueue(ctx)
	status, _ = gaugeValue(t, r, "queue_collection_success")
	require.Equal(t, float64(1), status)
}

func TestConcurrentReplicasCountOneRecreation(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	r := metrics.New(true)
	ctx := context.Background()
	workers := make([]*streamWorker, 4)
	for i := range workers {
		workers[i] = NewWorker(cfg, rdb, &countingController{}, store, r).(*streamWorker)
	}
	requireGroup(t, workers[0])
	require.NoError(t, rdb.XGroupDestroy(ctx, workers[0].stream, workerGroup).Err())

	// Run them at once: sequential calls would pass even if BUSYGROUP counted
	// as a recreation, because only the first call would create anything.
	cause := errors.New("NOGROUP No such key or consumer group")
	recovered := make(chan bool, len(workers))
	for _, w := range workers {
		go func(w *streamWorker) { recovered <- w.recoverMissingGroup(ctx, cause) }(w)
	}
	for range workers {
		require.True(t, <-recovered)
	}
	require.Equal(t, float64(1), metricCount(t, r, "queue_group_recreated_total", "", ""))
}

func TestCancelledCollectionIsNotAnOutage(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	r := metrics.New(true)
	w := NewWorker(cfg, rdb, &countingController{}, store, r).(*streamWorker)
	requireGroup(t, w)
	w.observeQueue(context.Background())
	status, _ := gaugeValue(t, r, "queue_collection_success")
	require.Equal(t, float64(1), status)

	// Shutdown cancels the sampler mid-call; the last word on the queue must
	// not be a failure the adapter caused by stopping.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.observeQueue(ctx)
	status, _ = gaugeValue(t, r, "queue_collection_success")
	require.Equal(t, float64(1), status)
}

func TestWorkerHealthNeedsTheConsumerGroupNotJustAServer(t *testing.T) {
	server, rdb, store, cfg := setupQueue(t)
	w := NewWorker(cfg, rdb, &countingController{}, store, metrics.New(true)).(*streamWorker)
	ctx := context.Background()

	// The stream has to exist first: without it XInfoGroups fails on the missing
	// key, and "reading consumer groups of ..." would satisfy a substring check
	// for "consumer group" without the missing-group branch ever running.
	require.NoError(t, rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: w.stream, Values: map[string]any{"fixture": "1"},
	}).Err())
	// A stream nothing has subscribed to answers XLEN but delivers nothing.
	require.ErrorContains(t, w.Healthy(ctx), `consumer group "scanner" is missing`)
	requireGroup(t, w)
	require.NoError(t, w.Healthy(ctx))

	require.NoError(t, rdb.XGroupDestroy(ctx, w.stream, workerGroup).Err())
	require.ErrorContains(t, w.Healthy(ctx), `consumer group "scanner" is missing`)

	requireGroup(t, w)
	server.SetError("redis outage")
	require.ErrorContains(t, w.Healthy(ctx), "redis outage")
	server.SetError("")
	require.NoError(t, w.Healthy(ctx))
}

func TestWorkerIsActiveWhileItReadsOrRenewsALease(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	w := NewWorker(cfg, rdb, &countingController{}, store, metrics.New(true)).(*streamWorker)
	require.ErrorContains(t, w.Active(), "has not reached the queue")

	w.beat()
	require.NoError(t, w.Active())

	// A scan longer than three lease periods keeps beating through its lease
	// renewals; only a loop that stopped goes stale.
	w.heartbeat.Store(time.Now().Add(-2 * w.leaseDuration).Unix())
	require.NoError(t, w.Active())
	w.heartbeat.Store(time.Now().Add(-4 * w.leaseDuration).Unix())
	require.ErrorContains(t, w.Active(), "last reached the queue")
}

func TestStartedWorkerBeatsAndReportsHealthy(t *testing.T) {
	_, rdb, store, cfg := setupQueue(t)
	w := NewWorker(cfg, rdb, &countingController{}, store, metrics.New(true))
	ctx := context.Background()
	w.Start(ctx)
	t.Cleanup(w.Stop)
	require.Eventually(t, func() bool {
		return w.Active() == nil && w.Healthy(ctx) == nil
	}, 5*time.Second, 10*time.Millisecond)
}
