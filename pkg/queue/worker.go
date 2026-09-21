package queue

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	"github.com/container-registry/harbor-scanner-trivy/pkg/scan"
)

type Worker interface {
	Start(ctx context.Context)
	Stop()
}

type worker struct {
	metrics     *metrics.Recorder
	namespace   string
	concurrency int

	rdb    *redis.Client
	pubsub *redis.PubSub

	controller scan.Controller
}

func NewWorker(config etc.JobQueue, rdb *redis.Client, controller scan.Controller, recorders ...*metrics.Recorder) Worker {
	return &worker{
		metrics:     metrics.Optional(recorders),
		namespace:   config.Namespace,
		concurrency: config.WorkerConcurrency,

		rdb: rdb,

		controller: controller,
	}
}

func (w *worker) Start(ctx context.Context) {
	w.pubsub = w.rdb.Subscribe(ctx, w.redisJobChannel())
	ch := w.pubsub.Channel()

	for i := 0; i < w.concurrency; i++ {
		go func() {
			w.subscribe(ctx, ch)
		}()
	}
}

func (w *worker) Stop() {
	slog.Debug("Job queue shutdown started")
	_ = w.pubsub.Close()
	slog.Debug("Job queue shutdown completed")
}

func (w *worker) redisJobChannel() string {
	return redisJobChannel(w.namespace)
}

func (w *worker) subscribe(ctx context.Context, ch <-chan *redis.Message) {
	for msg := range ch {
		chLog := slog.With(
			slog.String("channel", msg.Channel),
			slog.String("payload", msg.Payload),
		)
		chLog.Debug("Message subscribed")

		if err := w.scanArtifact(ctx, msg); err != nil {
			chLog.Error("Failed to scan artifact", slog.String("err", err.Error()))
			continue
		}
	}
}

func (w *worker) scanArtifact(ctx context.Context, msg *redis.Message) error {
	var job Job
	if err := json.Unmarshal([]byte(msg.Payload), &job); err != nil {
		w.metrics.Inc("job_dispatch_total", "decode_error")
		return xerrors.Errorf("unmarshaling scan request: %w", err)
	}

	if job.Args.ScanRequest == nil {
		w.metrics.Inc("job_dispatch_total", "decode_error")
		return xerrors.New("scan request is missing")
	}
	// Lock the job so that other workers won't process it.
	nx, err := w.rdb.SetNX(ctx, redisLockKey(w.namespace, job.ID()), "", 5*time.Minute).Result()
	if err != nil {
		w.metrics.Inc("job_dispatch_total", "lock_error")
		return xerrors.Errorf("redis lock: %w", err)
	} else if !nx {
		w.metrics.Inc("job_dispatch_total", "lock_busy")
		slog.Debug("Skip the locked job", slog.String("scan_job_id", job.Key.ID))
		return nil
	}

	w.metrics.Inc("job_dispatch_total", "lock_acquired")
	if age := time.Since(job.EnqueuedAt); !job.EnqueuedAt.IsZero() && age >= 0 {
		capability, _ := metrics.JobLabels(job.Key)
		w.metrics.Observe("queue_wait_duration_seconds", age.Seconds(), capability)
	}
	slog.Debug("Executing enqueued scan job", slog.String("scan_job_id", job.Key.ID))
	return w.controller.Scan(ctx, job.Key, job.Args.ScanRequest)
}

func redisLockKey(namespace, jobID string) string {
	return redisJobChannel(namespace) + ":lock:" + jobID
}
