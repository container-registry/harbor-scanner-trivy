package etc

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/redis/go-redis/v9"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	Metrics    Metrics
	API        API
	Trivy      Trivy
	RedisStore RedisStore
	JobQueue   JobQueue
	RedisPool  RedisPool
}

// Metrics controls bounded background observations; scraping never initiates collection.
type Metrics struct {
	CollectionInterval time.Duration `env:"SCANNER_METRICS_COLLECTION_INTERVAL" envDefault:"1m"`
	CollectionTimeout  time.Duration `env:"SCANNER_METRICS_COLLECTION_TIMEOUT" envDefault:"5s"`
	CacheSizeEnabled   bool          `env:"SCANNER_METRICS_CACHE_SIZE_ENABLED" envDefault:"false"`
	CacheMaxFiles      int           `env:"SCANNER_METRICS_CACHE_MAX_FILES" envDefault:"10000"`
}

type Trivy struct {
	CacheBackend      string        `env:"SCANNER_TRIVY_CACHE_BACKEND" envDefault:"fs"`
	CacheTTL          time.Duration `env:"SCANNER_TRIVY_CACHE_TTL" envDefault:"168h"`
	CacheRedisTLS     bool          `env:"SCANNER_TRIVY_CACHE_REDIS_TLS"`
	CacheRedisCA      string        `env:"SCANNER_TRIVY_CACHE_REDIS_CA"`
	CacheRedisCert    string        `env:"SCANNER_TRIVY_CACHE_REDIS_CERT"`
	CacheRedisKey     string        `env:"SCANNER_TRIVY_CACHE_REDIS_KEY"`
	CacheDir          string        `env:"SCANNER_TRIVY_CACHE_DIR" envDefault:"/home/scanner/.cache/trivy"`
	ReportsDir        string        `env:"SCANNER_TRIVY_REPORTS_DIR" envDefault:"/home/scanner/.cache/reports"`
	DebugMode         bool          `env:"SCANNER_TRIVY_DEBUG_MODE" envDefault:"false"`
	VulnType          string        `env:"SCANNER_TRIVY_VULN_TYPE" envDefault:"os,library"`
	Scanners          string        `env:"SCANNER_TRIVY_SECURITY_CHECKS" envDefault:"vuln"`
	Severity          string        `env:"SCANNER_TRIVY_SEVERITY" envDefault:"UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"`
	IgnoreUnfixed     bool          `env:"SCANNER_TRIVY_IGNORE_UNFIXED" envDefault:"false"`
	IgnorePolicy      string        `env:"SCANNER_TRIVY_IGNORE_POLICY"`
	SkipDBUpdate      bool          `env:"SCANNER_TRIVY_SKIP_UPDATE" envDefault:"false"`
	SkipJavaDBUpdate  bool          `env:"SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE" envDefault:"false"`
	DBRepository      string        `env:"SCANNER_TRIVY_DB_REPOSITORY"`
	JavaDBRepository  string        `env:"SCANNER_TRIVY_JAVA_DB_REPOSITORY"`
	OfflineScan       bool          `env:"SCANNER_TRIVY_OFFLINE_SCAN" envDefault:"false"`
	GitHubToken       string        `env:"SCANNER_TRIVY_GITHUB_TOKEN"`
	Insecure          bool          `env:"SCANNER_TRIVY_INSECURE" envDefault:"false"`
	VEXSource         string        `env:"SCANNER_TRIVY_VEX_SOURCE"`
	SkipVEXRepoUpdate bool          `env:"SCANNER_TRIVY_SKIP_VEX_REPO_UPDATE" envDefault:"false"`
	Timeout           time.Duration `env:"SCANNER_TRIVY_TIMEOUT" envDefault:"5m0s"`
	UseSBOMAccessory  bool          `env:"SCANNER_TRIVY_USE_SBOM_ACCESSORY" envDefault:"false"`
}

type API struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ClientCAs      []string      `env:"SCANNER_API_SERVER_CLIENT_CAS"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_SERVER_IDLE_TIMEOUT" envDefault:"60s"`
	MetricsEnabled bool          `env:"SCANNER_API_SERVER_METRICS_ENABLED" envDefault:"true"`
}

func (c *API) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

type RedisStore struct {
	Namespace string `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:data-store"`
	// Defaulted in GetConfig from the Trivy timeout; see deriveScanJobTTL.
	ScanJobTTL time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL"`
}

type JobQueue struct {
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:job-queue"`
	WorkerConcurrency int    `env:"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY" envDefault:"1"`
}

type RedisPool struct {
	URL               string        `env:"SCANNER_REDIS_URL" envDefault:"redis://localhost:6379"`
	MaxActive         int           `env:"SCANNER_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	MaxIdle           int           `env:"SCANNER_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	IdleTimeout       time.Duration `env:"SCANNER_REDIS_POOL_IDLE_TIMEOUT" envDefault:"5m"`
	ConnectionTimeout time.Duration `env:"SCANNER_REDIS_POOL_CONNECTION_TIMEOUT" envDefault:"1s"`
	ReadTimeout       time.Duration `env:"SCANNER_REDIS_POOL_READ_TIMEOUT" envDefault:"1s"`
	WriteTimeout      time.Duration `env:"SCANNER_REDIS_POOL_WRITE_TIMEOUT" envDefault:"1s"`
}

func LogLevel() slog.Level {
	if value, ok := os.LookupEnv("SCANNER_LOG_LEVEL"); ok {
		switch strings.ToLower(value) {
		case "error":
			return slog.LevelError
		case "warn", "warning":
			return slog.LevelWarn
		case "info":
			return slog.LevelInfo
		case "trace", "debug":
			return slog.LevelDebug
		}
		return slog.LevelInfo
	}
	return slog.LevelInfo
}

func GetConfig() (Config, error) {
	var cfg Config
	err := env.Parse(&cfg)
	if err != nil {
		return cfg, err
	}

	if cfg.API.MetricsEnabled && (cfg.Metrics.CollectionInterval < time.Second || cfg.Metrics.CollectionTimeout <= 0 || cfg.Metrics.CollectionTimeout > cfg.Metrics.CollectionInterval || cfg.Metrics.CacheMaxFiles < 1 || cfg.Metrics.CacheMaxFiles > 1000000) {
		return cfg, fmt.Errorf("invalid metrics collection settings: interval must be >=1s, timeout in (0, interval], and max files in [1, 1000000]")
	}

	if _, ok := os.LookupEnv("SCANNER_TRIVY_DEBUG_MODE"); !ok {
		if LogLevel() == slog.LevelDebug {
			cfg.Trivy.DebugMode = true
		}
	}

	if cfg.Trivy.Timeout <= 0 || cfg.Trivy.Timeout > maxTrivyTimeout {
		return cfg, fmt.Errorf("SCANNER_TRIVY_TIMEOUT must be in (0, %s], got %s", maxTrivyTimeout, cfg.Trivy.Timeout)
	}
	if cfg.JobQueue.WorkerConcurrency != 1 {
		return cfg, fmt.Errorf("SCANNER_JOB_QUEUE_WORKER_CONCURRENCY must be 1; scale adapter pods with separate database volumes and a dedicated Redis/Valkey scan cache")
	}
	if err := validateCache(cfg.Trivy); err != nil {
		return cfg, err
	}

	if cfg.RedisStore.ScanJobTTL <= 0 {
		if cfg.RedisStore.ScanJobTTL < 0 {
			slog.Warn("Ignoring non-positive SCANNER_STORE_REDIS_SCAN_JOB_TTL, deriving from Trivy timeout",
				slog.Duration("scan_job_ttl", cfg.RedisStore.ScanJobTTL))
		}
		cfg.RedisStore.ScanJobTTL = deriveScanJobTTL(cfg.Trivy.Timeout)
	}

	return cfg, nil
}

func validateCache(cfg Trivy) error {
	switch cfg.CacheBackend {
	case "fs", "memory":
		if cfg.CacheRedisTLS || cfg.CacheRedisCA != "" || cfg.CacheRedisCert != "" || cfg.CacheRedisKey != "" {
			return fmt.Errorf("redis TLS settings require a Redis scan cache")
		}
		return nil
	}
	if !strings.HasPrefix(cfg.CacheBackend, "redis://") && !strings.HasPrefix(cfg.CacheBackend, "rediss://") {
		return fmt.Errorf("SCANNER_TRIVY_CACHE_BACKEND must be fs, memory, or a redis:// or rediss:// URL; Sentinel is not supported")
	}
	if _, err := redis.ParseURL(cfg.CacheBackend); err != nil {
		// Parse errors may include credentials. Never echo the URL or error.
		return fmt.Errorf("SCANNER_TRIVY_CACHE_BACKEND contains an invalid Redis URL")
	}
	if cfg.CacheTTL <= 0 {
		return fmt.Errorf("SCANNER_TRIVY_CACHE_TTL must be positive for a Redis scan cache")
	}
	if cfg.CacheRedisCA != "" || cfg.CacheRedisCert != "" || cfg.CacheRedisKey != "" {
		if cfg.CacheRedisCA == "" || cfg.CacheRedisCert == "" || cfg.CacheRedisKey == "" {
			return fmt.Errorf("redis scan cache TLS requires CA, certificate, and key together")
		}
	}
	return nil
}

// maxTrivyTimeout bounds SCANNER_TRIVY_TIMEOUT to something sane; generous
// beyond any real scan, and it keeps the TTL derivation from overflowing.
const maxTrivyTimeout = 24 * time.Hour

// deriveScanJobTTL retains the historical default for Harbor report polling.
// Durable queue metadata and reports do not expire until acknowledgement;
// this TTL applies only once the delivery has completed.
func deriveScanJobTTL(trivyTimeout time.Duration) time.Duration {
	return 2*trivyTimeout + 3*time.Second
}
