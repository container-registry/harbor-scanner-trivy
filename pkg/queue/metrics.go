package queue

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Sample between scans to avoid another background Redis connection per pod.
// A busy pod's sample can be as old as its current scan timeout.
func (w *streamWorker) observeQueue(ctx context.Context) {
	if depth, err := w.rdb.XLen(ctx, w.stream).Result(); err == nil {
		w.metrics.Set("queue_unacknowledged_jobs", float64(depth))
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
	}
}
