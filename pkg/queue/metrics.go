package queue

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Collection runs independently of scans using the shared Redis client.
func (w *streamWorker) monitorQueue(ctx context.Context) {
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
	success := true
	if count, err := w.rdb.HLen(ctx, w.stream+":quarantine").Result(); err == nil {
		w.metrics.Set("queue_quarantined_jobs", float64(count))
	} else {
		success = false
		w.metrics.Delete("queue_quarantined_jobs")
	}
	if depth, err := w.rdb.XLen(ctx, w.stream).Result(); err == nil {
		w.metrics.Set("queue_unacknowledged_jobs", float64(depth))
	} else {
		success = false
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
		success = false
		w.metrics.Delete("queue_oldest_age_seconds")
	}
	if success {
		w.metrics.Set("queue_collection_success", 1)
		w.metrics.Set("queue_collection_last_success_timestamp_seconds", float64(time.Now().Unix()))
	} else {
		w.metrics.Set("queue_collection_success", 0)
	}
}
