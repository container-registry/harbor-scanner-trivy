package queue

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
)

func TestMalformedDeliveryIsPreservedWithoutBlockingValidWork(t *testing.T) {
	_, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	stream := redisJobStream(cfg.Namespace)
	fields := map[string]interface{}{"job": "broken JSON", "unknown_field": "retained"}
	id, err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: fields}).Result()
	require.NoError(t, err)
	_, err = NewEnqueuer(cfg, s).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	r := metrics.New(true)
	w := NewWorker(cfg, rdb, scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		return s.UpdateStatus(ctx, key, job.Finished)
	}), s, r).(*streamWorker)
	w.Start(ctx)
	t.Cleanup(w.Stop)
	require.Eventually(t, func() bool { return rdb.XLen(ctx, stream).Val() == 0 }, 3*time.Second, 10*time.Millisecond)
	w.Stop()
	payload, err := rdb.HGet(ctx, stream+":quarantine", id).Result()
	require.NoError(t, err)
	var stored map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(payload), &stored))
	require.Equal(t, fields, stored)
	require.EqualValues(t, 0, rdb.XPending(ctx, stream, workerGroup).Val().Count)
	w.observeQueue(ctx)
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	var count float64
	for _, f := range families {
		if f.GetName() == metrics.Prefix+"queue_quarantined_jobs" {
			count = f.Metric[0].GetGauge().GetValue()
		}
	}
	require.EqualValues(t, 1, count)
	// Retrying stale delivery data must not create another quarantine record.
	require.NoError(t, w.quarantine(ctx, redis.XMessage{ID: id, Values: fields}))
	require.EqualValues(t, 1, rdb.HLen(ctx, stream+":quarantine").Val())
}

func TestFailedQuarantinePreservesPendingDelivery(t *testing.T) {
	_, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	w := NewWorker(cfg, rdb, nil, s).(*streamWorker)
	require.NoError(t, rdb.XGroupCreateMkStream(ctx, w.stream, workerGroup, "0").Err())
	id, err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: w.stream, Values: map[string]interface{}{"job": "invalid"}}).Result()
	require.NoError(t, err)
	streams, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{Group: workerGroup, Consumer: w.consumer, Streams: []string{w.stream, ">"}, Count: 1}).Result()
	require.NoError(t, err)
	// Wrong-type storage simulates a failed quarantine write.
	require.NoError(t, rdb.Set(ctx, w.stream+":quarantine", "wrong type", 0).Err())
	require.Error(t, w.process(ctx, streams[0].Messages[0]))
	require.EqualValues(t, 1, rdb.XLen(ctx, w.stream).Val())
	require.EqualValues(t, 1, rdb.XPending(ctx, w.stream, workerGroup).Val().Count)
	require.NoError(t, rdb.Del(ctx, w.stream+":quarantine").Err())
	require.NoError(t, w.process(ctx, streams[0].Messages[0]))
	require.True(t, rdb.HExists(ctx, w.stream+":quarantine", id).Val())
	require.Zero(t, rdb.XLen(ctx, w.stream).Val())
}
