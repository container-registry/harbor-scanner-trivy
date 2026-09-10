package queue

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence"
	storedb "github.com/container-registry/harbor-scanner-trivy/pkg/persistence/redis"
)

type scanFunc func(context.Context, job.ScanJobKey, *harbor.ScanRequest) error

func (f scanFunc) Scan(ctx context.Context, key job.ScanJobKey, req *harbor.ScanRequest) error {
	return f(ctx, key, req)
}

func TestWorkersRunDifferentJobsConcurrently(t *testing.T) {
	_, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	started := make(chan string, 2)
	release := make(chan struct{})
	controller := scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		started <- key.ID
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return s.UpdateStatus(ctx, key, job.Finished)
	})
	for range 2 {
		w := NewWorker(cfg, rdb, controller, s)
		w.Start(ctx)
		t.Cleanup(w.Stop)
	}
	for range 2 {
		_, err := NewEnqueuer(cfg, rdb, s).Enqueue(ctx, testRequest())
		require.NoError(t, err)
	}
	ids := make(map[string]bool)
	for range 2 {
		select {
		case id := <-started:
			ids[id] = true
		case <-time.After(3 * time.Second):
			t.Fatal("workers did not scan concurrently")
		}
	}
	require.Len(t, ids, 2)
	close(release)
	require.Eventually(t, func() bool { return rdb.XLen(ctx, redisJobStream(cfg.Namespace)).Val() == 0 }, 3*time.Second, 10*time.Millisecond)
}

func TestCancelledWorkerLeavesJobForRecovery(t *testing.T) {
	mr, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	started := make(chan struct{})
	w1 := NewWorker(cfg, rdb, scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		if err := s.UpdateStatus(ctx, key, job.Pending); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}), s)
	w1.(*streamWorker).leaseDuration = 150 * time.Millisecond
	w1.Start(ctx)
	t.Cleanup(w1.Stop)
	id, err := NewEnqueuer(cfg, rdb, s).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start")
	}
	w1.Stop()
	mr.FastForward(2 * time.Minute)
	done := make(chan struct{}, 1)
	w2 := NewWorker(cfg, rdb, scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		if err := s.UpdateStatus(ctx, key, job.Finished); err != nil {
			return err
		}
		done <- struct{}{}
		return nil
	}), s)
	w2.(*streamWorker).leaseDuration = 150 * time.Millisecond
	w2.Start(ctx)
	t.Cleanup(w2.Stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled job was not reclaimed")
	}
	state, err := s.Get(ctx, job.ScanJobKey{ID: id, MIMEType: api.MimeTypeSecurityVulnerabilityReport})
	require.NoError(t, err)
	require.Equal(t, job.Finished, state.Status)
}

func TestLeaseRenewalPreventsDuplicateLongScan(t *testing.T) {
	_, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	var calls atomic.Int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	controller := scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return s.UpdateStatus(ctx, key, job.Finished)
	})
	for range 2 {
		w := NewWorker(cfg, rdb, controller, s).(*streamWorker)
		w.leaseDuration = 150 * time.Millisecond
		w.Start(ctx)
		t.Cleanup(w.Stop)
	}
	_, err := NewEnqueuer(cfg, rdb, s).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("scan not started")
	}
	// Keep the scan active across several lease windows and an idle reader's poll.
	time.Sleep(1500 * time.Millisecond)
	require.EqualValues(t, 1, calls.Load())
	close(release)
	require.Eventually(t, func() bool { return rdb.XLen(ctx, redisJobStream(cfg.Namespace)).Val() == 0 }, 3*time.Second, 10*time.Millisecond)
}

func TestLostLeaseFencesJobWrites(t *testing.T) {
	_, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	id, err := NewEnqueuer(cfg, rdb, s).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	key := job.ScanJobKey{ID: id, MIMEType: api.MimeTypeSecurityVulnerabilityReport}
	require.NoError(t, rdb.Set(ctx, "lease", "new-owner", time.Minute).Err())
	stale := persistence.WithLease(ctx, "lease", "old-owner")
	require.ErrorContains(t, s.UpdateStatus(stale, key, job.Finished), "ownership lost")
	require.ErrorContains(t, s.UpdateReport(stale, key, harbor.ScanReport{}), "ownership lost")
	state, err := s.Get(ctx, key)
	require.NoError(t, err)
	require.Equal(t, job.Queued, state.Status)
}

func TestCompletedJobSurvivesUntilAcknowledgementWithoutRescan(t *testing.T) {
	mr, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	id, err := NewEnqueuer(cfg, rdb, s).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	key := job.ScanJobKey{ID: id, MIMEType: api.MimeTypeSecurityVulnerabilityReport}
	require.NoError(t, s.UpdateStatus(ctx, key, job.Finished))
	mr.FastForward(time.Hour)
	var calls atomic.Int32
	w := NewWorker(cfg, rdb, scanFunc(func(context.Context, job.ScanJobKey, *harbor.ScanRequest) error {
		calls.Add(1)
		return nil
	}), s)
	w.Start(ctx)
	t.Cleanup(w.Stop)
	require.Eventually(t, func() bool { return rdb.XLen(ctx, redisJobStream(cfg.Namespace)).Val() == 0 }, 3*time.Second, 10*time.Millisecond)
	require.Zero(t, calls.Load())
	state, err := s.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, state)
	mr.FastForward(2 * time.Second)
	state, err = s.Get(ctx, key)
	require.NoError(t, err)
	require.Nil(t, state, "completed metadata expires after acknowledgement")
}

func setupQueue(t *testing.T) (*miniredis.Miniredis, *redis.Client, persistence.Store, etc.JobQueue) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	s := storedb.NewStore(etc.RedisStore{Namespace: "test:data", ScanJobTTL: time.Second}, rdb)
	return mr, rdb, s, etc.JobQueue{Namespace: "test:queue", WorkerConcurrency: 1}
}

func testRequest() harbor.ScanRequest {
	return harbor.ScanRequest{Capabilities: []harbor.Capability{{
		Type:              harbor.CapabilityTypeVulnerability,
		ProducesMIMETypes: []api.MIMEType{api.MimeTypeSecurityVulnerabilityReport},
	}}}
}

func TestAcceptedJobSurvivesNoWorkers(t *testing.T) {
	mr, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	id, err := NewEnqueuer(cfg, rdb, s).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	mr.FastForward(time.Hour)
	key := job.ScanJobKey{ID: id, MIMEType: api.MimeTypeSecurityVulnerabilityReport}
	queued, err := s.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, queued, "accepted queued work must not expire before a worker starts")
	done := make(chan struct{}, 1)
	w := NewWorker(cfg, rdb, scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		if err := s.UpdateStatus(ctx, key, job.Finished); err != nil {
			return err
		}
		done <- struct{}{}
		return nil
	}), s)
	w.Start(ctx)
	t.Cleanup(w.Stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("job was not recovered")
	}
}

func TestRepeatedInterruptionsReachVisibleRetryLimit(t *testing.T) {
	_, rdb, s, cfg := setupQueue(t)
	ctx := context.Background()
	id, err := NewEnqueuer(cfg, rdb, s).Enqueue(ctx, testRequest())
	require.NoError(t, err)
	key := job.ScanJobKey{ID: id, MIMEType: api.MimeTypeSecurityVulnerabilityReport}
	var calls atomic.Int32
	w := NewWorker(cfg, rdb, scanFunc(func(ctx context.Context, key job.ScanJobKey, _ *harbor.ScanRequest) error {
		calls.Add(1)
		if err := s.UpdateStatus(ctx, key, job.Pending); err != nil {
			return err
		}
		return errors.New("cache unavailable")
	}), s).(*streamWorker)
	w.leaseDuration = 150 * time.Millisecond
	w.Start(ctx)
	t.Cleanup(w.Stop)
	require.Eventually(t, func() bool {
		state, err := s.Get(ctx, key)
		return err == nil && state != nil && state.Status == job.Failed && state.Error != ""
	}, 6*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 3, calls.Load())
	require.Eventually(t, func() bool { return rdb.XLen(ctx, redisJobStream(cfg.Namespace)).Val() == 0 }, time.Second, 10*time.Millisecond)
	w.Stop()
	consumers, err := rdb.XInfoConsumers(ctx, redisJobStream(cfg.Namespace), workerGroup).Result()
	require.NoError(t, err)
	require.Empty(t, consumers, "a stopped consumer with no pending work is removed")
}
