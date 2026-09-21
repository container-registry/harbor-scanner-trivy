package etc

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Envs map[string]string

func TestGetLogLevel(t *testing.T) {
	testCases := []struct {
		Name             string
		Envs             Envs
		ExpectedLogLevel slog.Level
	}{
		{
			Name:             "Should return default log level when env is not set",
			ExpectedLogLevel: slog.LevelInfo,
		},
		{
			Name: "Should return default log level when env has invalid value",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "unknown_level",
			},
			ExpectedLogLevel: slog.LevelInfo,
		},
		{
			Name: "Should return log level set as env",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "debug",
			},
			ExpectedLogLevel: slog.LevelDebug,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setEnvs(t, tc.Envs)
			assert.Equal(t, tc.ExpectedLogLevel, LogLevel())
		})
	}
}

func TestExplicitlyEmptyValueOverridesTheDefault(t *testing.T) {
	// The chart renders imageSrc: "" as SCANNER_TRIVY_IMAGE_SRC="", which has
	// to mean "leave the flag off" rather than fall back to the default.
	t.Run("set to empty", func(t *testing.T) {
		setEnvs(t, Envs{"SCANNER_TRIVY_IMAGE_SRC": ""})
		cfg, err := GetConfig()
		require.NoError(t, err)
		require.Empty(t, cfg.Trivy.ImageSrc)
	})
	t.Run("not set at all", func(t *testing.T) {
		// t.Setenv above restores whatever the test process inherited, which is
		// not the same as the variable being absent. Only absence reaches the
		// envDefault, so this subtest has to make it absent itself.
		unsetEnv(t, "SCANNER_TRIVY_IMAGE_SRC")
		cfg, err := GetConfig()
		require.NoError(t, err)
		require.Equal(t, "remote", cfg.Trivy.ImageSrc)
	})
}

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedError  error
		expectedConfig Config
	}{
		{
			name: "Should enable Trivy debug mode when log level is set to debug",
			envs: Envs{
				"SCANNER_LOG_LEVEL": "debug",
			},
			expectedConfig: Config{
				Metrics: Metrics{CollectionInterval: time.Minute, CollectionTimeout: 5 * time.Second, CacheMaxFiles: 10000},
				API: API{
					Addr:           ":8080",
					ReadTimeout:    parseDuration(t, "15s"),
					WriteTimeout:   parseDuration(t, "15s"),
					IdleTimeout:    parseDuration(t, "60s"),
					MetricsEnabled: true,
				},
				Trivy: Trivy{
					CacheBackend: "fs",
					CacheTTL:     168 * time.Hour,
					DebugMode:    true,
					CacheDir:     "/home/scanner/.cache/trivy",
					ReportsDir:   "/home/scanner/.cache/reports",
					VulnType:     "os,library",
					Scanners:     "vuln",
					Severity:     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					Insecure:     false,
					GitHubToken:  "",
					Timeout:      parseDuration(t, "5m0s"),

					ImageSrc:         "remote",
					SkipVersionCheck: true,
					DisableTelemetry: true,
				},
				RedisPool: RedisPool{
					URL:               "redis://localhost:6379",
					MaxActive:         5,
					MaxIdle:           5,
					IdleTimeout:       parseDuration(t, "5m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
				RedisStore: RedisStore{
					Namespace:  "harbor.scanner.trivy:data-store",
					ScanJobTTL: parseDuration(t, "10m3s"),
				},
				JobQueue: JobQueue{
					Namespace:         "harbor.scanner.trivy:job-queue",
					WorkerConcurrency: 1,
				},
			},
		},
		{
			name: "Should return default config",
			expectedConfig: Config{
				Metrics: Metrics{CollectionInterval: time.Minute, CollectionTimeout: 5 * time.Second, CacheMaxFiles: 10000},
				API: API{
					Addr:           ":8080",
					ReadTimeout:    parseDuration(t, "15s"),
					WriteTimeout:   parseDuration(t, "15s"),
					IdleTimeout:    parseDuration(t, "60s"),
					MetricsEnabled: true,
				},
				Trivy: Trivy{
					CacheBackend: "fs",
					CacheTTL:     168 * time.Hour,
					DebugMode:    false,
					CacheDir:     "/home/scanner/.cache/trivy",
					ReportsDir:   "/home/scanner/.cache/reports",
					VulnType:     "os,library",
					Scanners:     "vuln",
					Severity:     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					Insecure:     false,
					GitHubToken:  "",
					Timeout:      parseDuration(t, "5m0s"),

					ImageSrc:         "remote",
					SkipVersionCheck: true,
					DisableTelemetry: true,
				},
				RedisPool: RedisPool{
					URL:               "redis://localhost:6379",
					MaxActive:         5,
					MaxIdle:           5,
					IdleTimeout:       parseDuration(t, "5m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
				RedisStore: RedisStore{
					Namespace:  "harbor.scanner.trivy:data-store",
					ScanJobTTL: parseDuration(t, "10m3s"),
				},
				JobQueue: JobQueue{
					Namespace:         "harbor.scanner.trivy:job-queue",
					WorkerConcurrency: 1,
				},
			},
		},
		{
			name: "Should overwrite default config with environment variables",
			envs: Envs{
				"SCANNER_API_SERVER_ADDR":            ":4200",
				"SCANNER_API_SERVER_TLS_CERTIFICATE": "/certs/tls.crt",
				"SCANNER_API_SERVER_TLS_KEY":         "/certs/tls.key",
				"SCANNER_API_SERVER_CLIENT_CAS":      "/certs/tls1.crt,/certs/tls2.crt",
				"SCANNER_API_SERVER_TLS_MIN_VERSION": "1.0",
				"SCANNER_API_SERVER_TLS_MAX_VERSION": "1.2",
				"SCANNER_API_SERVER_READ_TIMEOUT":    "1h",
				"SCANNER_API_SERVER_WRITE_TIMEOUT":   "2m",
				"SCANNER_API_SERVER_IDLE_TIMEOUT":    "3m10s",

				"SCANNER_TRIVY_CACHE_DIR":            "/home/scanner/trivy-cache",
				"SCANNER_TRIVY_REPORTS_DIR":          "/home/scanner/trivy-reports",
				"SCANNER_TRIVY_DEBUG_MODE":           "true",
				"SCANNER_TRIVY_VULN_TYPE":            "os,library",
				"SCANNER_TRIVY_SECURITY_CHECKS":      "vuln",
				"SCANNER_TRIVY_SEVERITY":             "CRITICAL",
				"SCANNER_TRIVY_IGNORE_UNFIXED":       "true",
				"SCANNER_TRIVY_INSECURE":             "true",
				"SCANNER_TRIVY_SKIP_UPDATE":          "true",
				"SCANNER_TRIVY_OFFLINE_SCAN":         "true",
				"SCANNER_TRIVY_GITHUB_TOKEN":         "<GITHUB_TOKEN>",
				"SCANNER_TRIVY_TIMEOUT":              "15m30s",
				"SCANNER_TRIVY_VEX_SOURCE":           "oci",
				"SCANNER_TRIVY_SKIP_VEX_REPO_UPDATE": "true",
				"SCANNER_TRIVY_IMAGE_SRC":            "docker",
				"SCANNER_TRIVY_SKIP_VERSION_CHECK":   "false",
				"SCANNER_TRIVY_DISABLE_TELEMETRY":    "false",
				"SCANNER_TRIVY_MAX_IMAGE_SIZE":       "5GB",
				"SCANNER_TRIVY_CHILD_GOMEMLIMIT":     "off",

				"SCANNER_STORE_REDIS_NAMESPACE":    "store.ns",
				"SCANNER_STORE_REDIS_SCAN_JOB_TTL": "2h45m15s",

				"SCANNER_JOB_QUEUE_REDIS_NAMESPACE":    "job-queue.ns",
				"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY": "1",

				"SCANNER_REDIS_URL":                  "redis://harbor-harbor-redis:6379",
				"SCANNER_REDIS_POOL_MAX_ACTIVE":      "3",
				"SCANNER_REDIS_POOL_MAX_IDLE":        "7",
				"SCANNER_REDIS_POOL_IDLE_TIMEOUT":    "3m",
				"SCANNER_API_SERVER_METRICS_ENABLED": "false",
			},
			expectedConfig: Config{
				Metrics: Metrics{CollectionInterval: time.Minute, CollectionTimeout: 5 * time.Second, CacheMaxFiles: 10000},
				API: API{
					Addr:           ":4200",
					TLSCertificate: "/certs/tls.crt",
					TLSKey:         "/certs/tls.key",
					ClientCAs: []string{
						"/certs/tls1.crt",
						"/certs/tls2.crt",
					},
					ReadTimeout:    parseDuration(t, "1h"),
					WriteTimeout:   parseDuration(t, "2m"),
					IdleTimeout:    parseDuration(t, "3m10s"),
					MetricsEnabled: false,
				},
				Trivy: Trivy{
					CacheBackend:      "fs",
					CacheTTL:          168 * time.Hour,
					CacheDir:          "/home/scanner/trivy-cache",
					ReportsDir:        "/home/scanner/trivy-reports",
					DebugMode:         true,
					VulnType:          "os,library",
					Scanners:          "vuln",
					Severity:          "CRITICAL",
					IgnoreUnfixed:     true,
					SkipDBUpdate:      true,
					SkipJavaDBUpdate:  false,
					OfflineScan:       true,
					Insecure:          true,
					GitHubToken:       "<GITHUB_TOKEN>",
					Timeout:           parseDuration(t, "15m30s"),
					VEXSource:         "oci",
					SkipVEXRepoUpdate: true,
					ImageSrc:          "docker",
					SkipVersionCheck:  false,
					DisableTelemetry:  false,
					MaxImageSize:      "5GB",
					ChildGoMemLimit:   "off",
				},
				RedisPool: RedisPool{
					URL:               "redis://harbor-harbor-redis:6379",
					MaxActive:         3,
					MaxIdle:           7,
					IdleTimeout:       parseDuration(t, "3m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
				RedisStore: RedisStore{
					Namespace:  "store.ns",
					ScanJobTTL: parseDuration(t, "2h45m15s"),
				},
				JobQueue: JobQueue{
					Namespace:         "job-queue.ns",
					WorkerConcurrency: 1,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setEnvs(t, tc.envs)
			config, err := GetConfig()
			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedConfig, config)
		})
	}
}

func TestScanJobTTLDerivation(t *testing.T) {
	testCases := []struct {
		name        string
		envs        Envs
		expectedTTL time.Duration
	}{
		{
			name:        "Derives 2x Trivy timeout plus 3s when unset",
			envs:        Envs{"SCANNER_TRIVY_TIMEOUT": "10m"},
			expectedTTL: parseDuration(t, "20m3s"),
		},
		{
			name:        "Explicit TTL wins over derivation",
			envs:        Envs{"SCANNER_TRIVY_TIMEOUT": "10m", "SCANNER_STORE_REDIS_SCAN_JOB_TTL": "1h"},
			expectedTTL: parseDuration(t, "1h"),
		},
		{
			name:        "Non-positive TTL falls back to derivation",
			envs:        Envs{"SCANNER_STORE_REDIS_SCAN_JOB_TTL": "-5m"},
			expectedTTL: parseDuration(t, "10m3s"),
		},
		{
			name:        "Zero TTL falls back to derivation",
			envs:        Envs{"SCANNER_STORE_REDIS_SCAN_JOB_TTL": "0"},
			expectedTTL: parseDuration(t, "10m3s"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setEnvs(t, tc.envs)
			config, err := GetConfig()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedTTL, config.RedisStore.ScanJobTTL)
		})
	}

	for _, timeout := range []string{"-2s", "0", "25h"} {
		t.Run("Rejects Trivy timeout "+timeout, func(t *testing.T) {
			setEnvs(t, Envs{"SCANNER_TRIVY_TIMEOUT": timeout})
			_, err := GetConfig()
			require.ErrorContains(t, err, "SCANNER_TRIVY_TIMEOUT")
		})
	}
}

func setEnvs(t *testing.T, envs Envs) {
	for k, v := range envs {
		t.Setenv(k, v)
	}
}

// unsetEnv removes a variable for the duration of the test and puts back what
// the process had, which t.Setenv cannot express: it only restores a value.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	original, had := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key))
	t.Cleanup(func() {
		if !had {
			require.NoError(t, os.Unsetenv(key))
			return
		}
		require.NoError(t, os.Setenv(key, original))
	})
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	duration, err := time.ParseDuration(s)
	require.NoError(t, err)
	return duration
}

func TestMetricsConfigurationValidation(t *testing.T) {
	for _, tc := range []struct{ name, value string }{{"SCANNER_METRICS_COLLECTION_INTERVAL", "0s"}, {"SCANNER_METRICS_COLLECTION_TIMEOUT", "0s"}, {"SCANNER_METRICS_COLLECTION_TIMEOUT", "2m"}, {"SCANNER_METRICS_CACHE_MAX_FILES", "0"}} {
		t.Run(tc.name+tc.value, func(t *testing.T) {
			t.Setenv("SCANNER_API_SERVER_METRICS_ENABLED", "true")
			t.Setenv("SCANNER_METRICS_COLLECTION_INTERVAL", "1m")
			t.Setenv("SCANNER_METRICS_COLLECTION_TIMEOUT", "5s")
			t.Setenv("SCANNER_METRICS_CACHE_MAX_FILES", "10000")
			t.Setenv(tc.name, tc.value)
			_, err := GetConfig()
			require.ErrorContains(t, err, "invalid metrics collection settings")
		})
	}
}
