package etc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDedicatedCacheConfig(t *testing.T) {
	t.Setenv("SCANNER_TRIVY_CACHE_BACKEND", "rediss://cache.example:6379/0")
	t.Setenv("SCANNER_TRIVY_CACHE_TTL", "48h")
	cfg, err := GetConfig()
	require.NoError(t, err)
	require.Equal(t, "rediss://cache.example:6379/0", cfg.Trivy.CacheBackend)
	require.Equal(t, 48*time.Hour, cfg.Trivy.CacheTTL)
}

func TestRejectUnsupportedScalingConfig(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"workers", "SCANNER_JOB_QUEUE_WORKER_CONCURRENCY", "2"},
		{"no workers", "SCANNER_JOB_QUEUE_WORKER_CONCURRENCY", "0"},
		{"backend", "SCANNER_TRIVY_CACHE_BACKEND", "postgres://host"},
		{"sentinel", "SCANNER_TRIVY_CACHE_BACKEND", "redis+sentinel://host/master"},
		{"expiry", "SCANNER_TRIVY_CACHE_TTL", "0"},
		{"partial TLS", "SCANNER_TRIVY_CACHE_REDIS_CA", "/ca.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SCANNER_TRIVY_CACHE_BACKEND", "redis://cache.example:6379/0")
			t.Setenv(tc.key, tc.value)
			_, err := GetConfig()
			require.Error(t, err)
		})
	}
}
