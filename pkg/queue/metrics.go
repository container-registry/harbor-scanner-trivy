package queue

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Collection runs independently of scans using the shared Redis client.
func (w *streamWorker) monitorQueue(ctx context.Context) {
	if w.metrics == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		w.observeQueue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *streamWorker) observeQueue(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var failure error
	failed := func(query string, err error) {
		w.metrics.Inc("queue_collection_errors_total", query)
		if failure == nil {
			failure = fmt.Errorf("%s: %w", query, err)
		}
	}
	if count, err := w.rdb.HLen(ctx, w.stream+":quarantine").Result(); err == nil {
		w.metrics.Set("queue_quarantined_jobs", float64(count))
	} else {
		failed("quarantine", err)
		w.metrics.Delete("queue_quarantined_jobs")
	}
	if depth, err := w.rdb.XLen(ctx, w.stream).Result(); err == nil {
		w.metrics.Set("queue_unacknowledged_jobs", float64(depth))
	} else {
		failed("length", err)
		w.metrics.Delete("queue_unacknowledged_jobs")
	}
	if messages, err := w.rdb.XRangeN(ctx, w.stream, "-", "+", 1).Result(); err == nil {
		age := float64(0)
		if len(messages) > 0 {
			stamp, _, _ := strings.Cut(messages[0].ID, "-")
			if ms, err := strconv.ParseInt(stamp, 10, 64); err == nil {
				age = max(0, time.Since(time.UnixMilli(ms)).Seconds())
			}
		}
		w.metrics.Set("queue_oldest_age_seconds", age)
	} else {
		failed("oldest", err)
		w.metrics.Delete("queue_oldest_age_seconds")
	}
	w.reportCollection(failure)
}

// reportCollection logs state changes only. Collection samples every ten
// seconds, so logging each failure would turn a Redis outage into a log flood
// while the counter and the success gauge already carry the rate.
func (w *streamWorker) reportCollection(failure error) {
	if failure != nil {
		w.metrics.Set("queue_collection_success", 0)
		if !w.collectionFailing {
			w.collectionFailing = true
			slog.Error("Queue metric collection failed", slog.String("err", failure.Error()))
		}
		return
	}
	w.metrics.Set("queue_collection_success", 1)
	w.metrics.Set("queue_collection_last_success_timestamp_seconds", float64(time.Now().Unix()))
	if w.collectionFailing {
		w.collectionFailing = false
		slog.Info("Queue metric collection recovered")
	}
}
