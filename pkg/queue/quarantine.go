package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// Preserve deliveries the worker cannot execute, an undecodable payload or a
// job key the store no longer has, outside the active stream for operator inspection.
// The hash is keyed by delivery ID so retries do not create duplicate copies.
// If preserving the payload fails, leave the original delivery recoverable.
var quarantineDelivery = redis.NewScript(`
	if redis.call('XLEN', KEYS[1]) == 0 then return 0 end
	local entry = redis.call('XRANGE', KEYS[1], ARGV[2], ARGV[2], 'COUNT', 1)
	if #entry == 0 then return 0 end
	redis.call('HSET', KEYS[2], ARGV[2], ARGV[3])
	redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
	redis.call('XDEL', KEYS[1], ARGV[2])
	return 1`)

// quarantinedDelivery is the hash value: the reason travels with the fields
// because the log line that names it is long gone when an operator inspects the key.
type quarantinedDelivery struct {
	Reason string         `json:"reason"`
	Fields map[string]any `json:"fields"`
}

func (w *streamWorker) quarantine(ctx context.Context, msg redis.XMessage, reason string) error {
	payload, err := json.Marshal(quarantinedDelivery{Reason: reason, Fields: msg.Values})
	if err != nil {
		return fmt.Errorf("preserving delivery %s: %w", msg.ID, err)
	}
	preserved, err := quarantineDelivery.Run(ctx, w.rdb, []string{w.stream, w.stream + ":quarantine"}, workerGroup, msg.ID, payload).Int()
	if err != nil {
		return fmt.Errorf("quarantining delivery %s: %w", msg.ID, err)
	}
	if preserved == 1 {
		slog.Error("Scan delivery quarantined", "delivery_id", msg.ID, "reason", reason)
	}
	return nil
}
