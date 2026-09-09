package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// RegisterRedis reads the shared client's in-memory pool statistics, never Redis
// keys or INFO. Raw cumulative counters reset with the client (or uint32 wrap).
func (r *Recorder) RegisterRedis(client *redis.Client) {
	if r == nil {
		return
	}
	add := func(name, help string, read func(*redis.PoolStats) float64, kind prometheus.ValueType, labels prometheus.Labels) {
		opts := prometheus.Opts{Name: Prefix + name, Help: help, ConstLabels: labels}
		if kind == prometheus.CounterValue {
			r.registry.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts(opts), func() float64 { return read(client.PoolStats()) }))
		} else {
			r.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts(opts), func() float64 { return read(client.PoolStats()) }))
		}
	}
	add("redis_pool_connections", "Client pool connections; total includes idle.", func(s *redis.PoolStats) float64 { return float64(s.TotalConns) }, prometheus.GaugeValue, prometheus.Labels{"state": "total"})
	add("redis_pool_connections", "Client pool connections; total includes idle.", func(s *redis.PoolStats) float64 { return float64(s.IdleConns) }, prometheus.GaugeValue, prometheus.Labels{"state": "idle"})
	add("redis_pool_requests_total", "Client connection pool hits/misses, not analysis-cache reuse.", func(s *redis.PoolStats) float64 { return float64(s.Hits) }, prometheus.CounterValue, prometheus.Labels{"result": "hit"})
	add("redis_pool_requests_total", "Client connection pool hits/misses, not analysis-cache reuse.", func(s *redis.PoolStats) float64 { return float64(s.Misses) }, prometheus.CounterValue, prometheus.Labels{"result": "miss"})
	add("redis_pool_timeouts_total", "Client pool wait timeouts.", func(s *redis.PoolStats) float64 { return float64(s.Timeouts) }, prometheus.CounterValue, nil)
	add("redis_pool_waits_total", "Client connection waits.", func(s *redis.PoolStats) float64 { return float64(s.WaitCount) }, prometheus.CounterValue, nil)
	add("redis_pool_wait_duration_seconds_total", "Accumulated client connection wait seconds.", func(s *redis.PoolStats) float64 { return float64(s.WaitDurationNs) / 1e9 }, prometheus.CounterValue, nil)
	add("redis_pool_stale_connections_total", "Stale client connections removed.", func(s *redis.PoolStats) float64 { return float64(s.StaleConns) }, prometheus.CounterValue, nil)
	add("redis_pool_size", "Client base pool size; not the hard connection limit.", func(*redis.PoolStats) float64 { return float64(client.Options().PoolSize) }, prometheus.GaugeValue, nil)
	add("redis_pool_max_active_connections", "Configured hard active-connection limit; zero means unlimited.", func(*redis.PoolStats) float64 { return float64(client.Options().MaxActiveConns) }, prometheus.GaugeValue, nil)
}
