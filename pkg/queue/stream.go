package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence"
	"github.com/container-registry/harbor-scanner-trivy/pkg/scan"
	"github.com/redis/go-redis/v9"
)

const workerGroup = "scanner"

// CheckBackend fails before the API accepts jobs if recovery is unavailable.
// Check the command rather than the server version to support Valkey too.
func CheckBackend(ctx context.Context, rdb *redis.Client) error {
	commands, err := rdb.Do(ctx, "COMMAND", "INFO", "XAUTOCLAIM").Slice()
	if err != nil {
		return fmt.Errorf("checking queue backend capabilities: %w", err)
	}
	if len(commands) != 1 || commands[0] == nil {
		return errors.New("scan queue requires Redis 6.2+ or compatible Valkey with XAUTOCLAIM")
	}
	return nil
}

var renewLease = redis.NewScript(`
	if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
	redis.call('PEXPIRE', KEYS[1], ARGV[2])
	redis.call('XCLAIM', KEYS[2], ARGV[3], ARGV[4], 0, ARGV[5], 'JUSTID')
	return 1`)

var releaseLease = redis.NewScript(`
	if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
	return 0`)

// Never delete a consumer with pending deliveries: Redis would discard their
// recovery records. Idle consumers left by terminated pods can otherwise grow
// without bound during autoscaling.
var cleanConsumers = redis.NewScript(`
	for _, consumer in ipairs(redis.call('XINFO', 'CONSUMERS', KEYS[1], ARGV[1])) do
		local info = {}
		for i = 1, #consumer, 2 do info[consumer[i]] = consumer[i+1] end
		if info.pending == 0 and (info.name == ARGV[2] or info.idle > tonumber(ARGV[3])) then
			redis.call('XGROUP', 'DELCONSUMER', KEYS[1], ARGV[1], info.name)
		end
	end
	return 1`)

type streamWorker struct {
	metrics          *metrics.Recorder
	stream, consumer string
	rdb              *redis.Client
	store            persistence.Store
	controller       scan.Controller
	leaseDuration    time.Duration
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

func NewWorker(config etc.JobQueue, rdb *redis.Client, controller scan.Controller, store persistence.Store, recorders ...*metrics.Recorder) Worker {
	return &streamWorker{
		metrics: metrics.Optional(recorders),
		stream:  redisJobStream(config.Namespace), consumer: makeIdentifier(), rdb: rdb,
		controller: controller, store: store, leaseDuration: time.Minute,
	}
}

func (w *streamWorker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	w.wg.Add(2)
	go func() { defer w.wg.Done(); w.run(ctx) }()
	go func() { defer w.wg.Done(); w.monitorQueue(ctx) }()
}

// Stop cancels active work and waits for it to exit. Unacknowledged deliveries
// remain in the stream for another pod; never start two CLI scans in one pod.
func (w *streamWorker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
}

func (w *streamWorker) run(ctx context.Context) {
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = cleanConsumers.Run(cleanup, w.rdb, []string{w.stream}, workerGroup, w.consumer, (2 * w.leaseDuration).Milliseconds()).Err()
	}()
	for ctx.Err() == nil {
		err := w.rdb.XGroupCreateMkStream(ctx, w.stream, workerGroup, "0").Err()
		if err == nil || strings.HasPrefix(err.Error(), "BUSYGROUP") {
			break
		}
		slog.Error("Initializing scan stream", "error", err)
		if !waitRetry(ctx) {
			return
		}
	}
	cursor := "0-0"
	var observed time.Time
	for ctx.Err() == nil {
		if time.Since(observed) >= 10*time.Second {
			_ = cleanConsumers.Run(ctx, w.rdb, []string{w.stream}, workerGroup, "", (2 * w.leaseDuration).Milliseconds()).Err()
			observed = time.Now()
		}
		messages, next, err := w.rdb.XAutoClaim(ctx, &redis.XAutoClaimArgs{
			Stream: w.stream, Group: workerGroup, Consumer: w.consumer,
			MinIdle: w.leaseDuration, Start: cursor, Count: 1,
		}).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			slog.Error("Recovering scan delivery", "error", err)
			if !waitRetry(ctx) {
				return
			}
			continue
		}
		cursor = next
		if cursor == "" {
			cursor = "0-0"
		}
		if len(messages) == 0 {
			streams, readErr := w.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group: workerGroup, Consumer: w.consumer, Streams: []string{w.stream, ">"}, Count: 1, Block: time.Second,
			}).Result()
			if errors.Is(readErr, redis.Nil) {
				continue
			}
			if readErr != nil {
				if ctx.Err() == nil {
					slog.Error("Reading scan delivery", "error", readErr)
				}
				if !waitRetry(ctx) {
					return
				}
				continue
			}
			for _, stream := range streams {
				messages = append(messages, stream.Messages...)
			}
		}
		for _, msg := range messages {
			if ctx.Err() != nil {
				return
			}
			if err := w.process(ctx, msg); err != nil && ctx.Err() == nil {
				slog.Error("Scan delivery remains pending for recovery", "delivery_id", msg.ID, "error", err)
			}
		}
	}
}

func (w *streamWorker) process(parent context.Context, msg redis.XMessage) error {
	var delivery Job
	payload, ok := msg.Values["job"].(string)
	if !ok || json.Unmarshal([]byte(payload), &delivery) != nil || delivery.Args.ScanRequest == nil {
		w.metrics.Inc("job_dispatch_total", "decode_error")
		return w.quarantine(parent, msg)
	}
	lockKey := w.stream + ":lease:" + msg.ID
	token := makeIdentifier()
	owned, err := w.rdb.SetNX(parent, lockKey, token, w.leaseDuration).Result()
	if err != nil {
		w.metrics.Inc("job_dispatch_total", "lock_error")
		return err
	}
	if !owned {
		w.metrics.Inc("job_dispatch_total", "lock_busy")
		return nil
	}
	claimedAt := time.Now()
	w.metrics.Inc("job_dispatch_total", "lock_acquired")
	ctx, cancel := context.WithCancel(persistence.WithLease(parent, lockKey, token))
	done := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(w.leaseDuration / 3)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				renewed, err := renewLease.Run(ctx, w.rdb, []string{lockKey, w.stream}, token,
					w.leaseDuration.Milliseconds(), workerGroup, w.consumer, msg.ID).Int()
				if err != nil || renewed != 1 {
					w.metrics.Inc("lease_losses_total")
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		close(done)
		cancel()
		<-heartbeatDone
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
		defer cleanupCancel()
		_ = releaseLease.Run(cleanup, w.rdb, []string{lockKey}, token).Err()
	}()
	state, err := w.store.Get(ctx, delivery.Key)
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("scan job metadata missing for %s", delivery.Key.ID)
	}
	if state.Status != job.Finished && state.Status != job.Failed {
		if state.Attempts >= 3 {
			if err := w.store.UpdateStatus(ctx, delivery.Key, job.Failed, "scan retry limit reached after interrupted or failed attempts"); err != nil {
				return err
			}
			return w.store.Acknowledge(ctx, delivery.Key, w.stream, workerGroup, msg.ID)
		}
		if state.Attempts > 0 {
			w.metrics.Inc("scan_retries_total")
		} else if age := claimedAt.Sub(delivery.EnqueuedAt); !delivery.EnqueuedAt.IsZero() && age >= 0 {
			capability, _ := metrics.JobLabels(delivery.Key)
			w.metrics.Observe("queue_wait_duration_seconds", age.Seconds(), capability)
		}
		if err := w.controller.Scan(ctx, delivery.Key, delivery.Args.ScanRequest); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return w.store.Acknowledge(ctx, delivery.Key, w.stream, workerGroup, msg.ID)
}

func waitRetry(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Second):
		return true
	}
}
