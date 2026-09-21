package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
)

type databaseMetadata struct {
	Version                             int
	UpdatedAt, NextUpdate, DownloadedAt time.Time
}

// Start samples metadata and filesystems in one bounded background loop. The
// returned function waits for cancellation/collection completion before shutdown.
//
// tempRoot is the directory the adapter gives its Trivy children as TMPDIR.
// It is passed in rather than derived here: pkg/trivy owns that contract and
// imports this package, so the naming cannot be duplicated on this side without
// the two drifting apart.
func (r *Recorder) Start(ctx context.Context, cfg etc.Config, adapterVersion, tempRoot string, ambassador ext.Ambassador) func() {
	if r == nil {
		return func() {}
	}
	r.version.ttl = 2 * cfg.Metrics.CollectionInterval
	r.Set("worker_concurrency", float64(cfg.JobQueue.WorkerConcurrency))
	backend := analysisCacheBackend(cfg.Trivy.CacheBackend)
	r.Set("analysis_cache_backend_info", 1, backend)
	r.Set("scan_timeout_seconds", cfg.Trivy.Timeout.Seconds())
	r.Set("scan_job_ttl_seconds", cfg.RedisStore.ScanJobTTL.Seconds())
	for _, db := range []string{"vulnerability", "java"} {
		enabled := !cfg.Trivy.SkipDBUpdate
		if db == "java" {
			enabled = !cfg.Trivy.SkipJavaDBUpdate
		}
		r.Set("db_updates_enabled", boolValue(enabled), db)
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		version := ""
		for {
			if ctx.Err() != nil {
				return
			}
			probed := r.probeEngine(ctx, cfg, ambassador, adapterVersion, version)
			if probed != "" {
				version = probed
			}
			r.collectMetadata(cfg.Trivy, probed != "")
			r.collectFilesystem(cfg.Trivy.CacheDir, "cache")
			r.collectFilesystem(cfg.Trivy.ReportsDir, "reports")
			// Trivy extracts layers under the temp directory, which is often a
			// different filesystem from the cache and fills up on its own.
			r.collectFilesystem(os.TempDir(), "tmp")
			if cfg.Metrics.CacheSizeEnabled {
				walkCtx, stop := context.WithTimeout(ctx, cfg.Metrics.CollectionTimeout)
				r.collectCache(walkCtx, cfg.Trivy.CacheDir, tempRoot, cfg.Metrics.CacheMaxFiles, backend)
				stop()
			}
			// Jitter avoids synchronized directory walks across scanner replicas.
			delay := cfg.Metrics.CollectionInterval + time.Duration(rand.Float64()*0.1*float64(cfg.Metrics.CollectionInterval))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// engineProbe is the subset of `trivy version --format json` the adapter reads.
// The database blocks are omitted until the database has been downloaded.
type engineProbe struct {
	Version         string
	VulnerabilityDB *struct{ Version int }
	JavaDB          *struct{ Version int }
}

// probeEngine samples the engine on every tick rather than once. The binary is
// replaced by image upgrades and both databases change schema under a running
// pod, so a reading taken at startup silently goes stale. It returns the engine
// version on success and an empty string on failure.
func (r *Recorder) probeEngine(ctx context.Context, cfg etc.Config, ambassador ext.Ambassador, adapterVersion, previous string) string {
	probeCtx, stop := context.WithTimeout(ctx, cfg.Metrics.CollectionTimeout)
	defer stop()
	// No TMPDIR and no --skip-version-check/--disable-telemetry here: measured
	// against v0.74.0, `trivy version --format json` creates nothing under
	// TMPDIR and contacts nothing, and those two are ScanFlagGroup flags that
	// the version subcommand rejects outright.
	cmd := exec.CommandContext(probeCtx, "trivy", "--cache-dir", cfg.Trivy.CacheDir, "version", "--format", "json")
	output, stderr, err := r.Run(probeCtx, "version", cmd, ambassador.RunCmd)
	var info engineProbe
	if err == nil {
		if err = json.Unmarshal(output, &info); err == nil && info.Version == "" {
			err = errors.New("version missing from engine output")
		}
	}
	if err != nil {
		slog.Debug("Trivy version probe failed",
			slog.String("err", err.Error()), slog.String("std_err", string(stderr)))
		for _, db := range []string{"vulnerability", "java"} {
			r.Delete("db_schema_version", db)
		}
		r.InvalidateVersion()
		return ""
	}
	// Keep the previous build_info series only while the binary is unchanged:
	// an upgraded engine would otherwise leave two series claiming to be current.
	if previous != "" && previous != info.Version {
		r.Delete("build_info", adapterVersion, previous)
	}
	r.Set("build_info", 1, adapterVersion, info.Version)
	for _, db := range []struct {
		name string
		meta *struct{ Version int }
	}{{"vulnerability", info.VulnerabilityDB}, {"java", info.JavaDB}} {
		// The engine omits the block until the database has been downloaded.
		// There is no schema version to report then, and a zero would read as
		// one; db_present already carries the absence.
		if db.meta == nil {
			r.Delete("db_schema_version", db.name)
			continue
		}
		r.Set("db_schema_version", float64(db.meta.Version), db.name)
	}
	r.cacheVersion(output)
	return info.Version
}

func (r *Recorder) collectMetadata(cfg etc.Trivy, versionOK bool) {
	ok := versionOK
	for _, db := range []struct{ name, dir, file string }{{"vulnerability", "db", "trivy.db"}, {"java", "java-db", "trivy-java.db"}} {
		root := filepath.Join(cfg.CacheDir, db.dir)
		file, fileErr := os.Stat(filepath.Join(root, db.file))
		f, err := os.Open(filepath.Join(root, "metadata.json"))
		var meta databaseMetadata
		if err == nil {
			err = json.NewDecoder(io.LimitReader(f, (1<<20)+1)).Decode(&meta)
			_ = f.Close()
			if err == nil && (meta.Version <= 0 || meta.UpdatedAt.IsZero()) {
				err = errors.New("incomplete database metadata")
			}
		}
		// Missing files are a valid absent DB observation; other failures are unknown.
		failed := (fileErr == nil && !file.Mode().IsRegular()) || (fileErr != nil && !errors.Is(fileErr, fs.ErrNotExist)) || (err != nil && !errors.Is(err, fs.ErrNotExist))
		present := fileErr == nil && file.Mode().IsRegular() && err == nil
		if failed {
			ok = false
			r.Delete("db_present", db.name)
		} else {
			r.Set("db_present", boolValue(present), db.name)
		}
		for metric, stamp := range map[string]time.Time{"db_updated_timestamp_seconds": meta.UpdatedAt, "db_next_update_timestamp_seconds": meta.NextUpdate, "db_downloaded_timestamp_seconds": meta.DownloadedAt} {
			if present && !stamp.IsZero() {
				r.Set(metric, float64(stamp.Unix()), db.name)
			} else {
				r.Delete(metric, db.name)
			}
		}
	}
	r.Set("metadata_collection_success", boolValue(ok))
	if ok {
		r.Set("metadata_last_success_timestamp_seconds", float64(time.Now().Unix()))
	}
}

func (r *Recorder) collectFilesystem(path, area string) {
	started := time.Now()
	capacity, available, inodes, err := filesystem(path)
	collector := area + "_filesystem"
	if err == nil {
		r.Set("storage_capacity_bytes", capacity, area)
		r.Set("storage_available_bytes", available, area)
		if inodes >= 0 {
			r.Set("storage_inodes_available", inodes, area)
		} else {
			r.Delete("storage_inodes_available", area)
		}
	} else {
		for _, name := range []string{"storage_capacity_bytes", "storage_available_bytes", "storage_inodes_available"} {
			r.Delete(name, area)
		}
	}
	r.collectionResult(collector, started, err)
}

func (r *Recorder) collectionResult(collector string, started time.Time, err error) {
	r.Set("storage_collection_success", boolValue(err == nil), collector)
	r.Observe("storage_collection_duration_seconds", time.Since(started).Seconds(), collector)
	if err == nil {
		r.Set("storage_last_success_timestamp_seconds", float64(time.Now().Unix()), collector)
	}
}

// Report only a bounded backend name, never a Redis URL or credentials.
func analysisCacheBackend(configured string) string {
	switch configured {
	case "", "fs":
		return "filesystem"
	case "memory":
		return "memory"
	default:
		if strings.HasPrefix(configured, "redis://") || strings.HasPrefix(configured, "rediss://") {
			return "redis"
		}
		return "unknown"
	}
}

func (r *Recorder) collectCache(ctx context.Context, root, tempRoot string, maxFiles int, backend string) {
	started := time.Now()
	remaining := maxFiles
	var firstErr error
	for _, part := range []struct{ kind, dir string }{{"analysis", "fanal"}, {"vulnerability_db", "db"}, {"java_db", "java-db"}} {
		// A previous filesystem backend may have left fanal files behind. They
		// are not the active cache and must not consume the collection budget.
		if part.kind == "analysis" && backend != "filesystem" {
			r.Delete("cache_size_bytes", part.kind)
			continue
		}
		path := filepath.Join(root, part.dir)
		size, err := directoryBytes(ctx, path, &remaining, failOnUnsupported)
		var pathErr *fs.PathError
		// An uninitialized cache part is empty. A vanished descendant or missing
		// cache root is an incomplete collection, not a zero-byte observation.
		if errors.As(err, &pathErr) && pathErr.Path == path && errors.Is(err, fs.ErrNotExist) {
			if rootInfo, rootErr := os.Stat(root); rootErr == nil && rootInfo.IsDir() {
				size, err = 0, nil
			}
		}
		if err != nil {
			r.Delete("cache_size_bytes", part.kind)
			firstErr = err
		} else {
			r.Set("cache_size_bytes", float64(size), part.kind)
		}
	}
	size, err := trivyTempBytes(ctx, tempRoot, &remaining)
	if err != nil {
		r.Delete("cache_size_bytes", "tmp_trivy")
		if firstErr == nil {
			firstErr = err
		}
	} else {
		r.Set("cache_size_bytes", float64(size), "tmp_trivy")
	}
	r.collectionResult("cache_size", started, firstErr)
}

// trivyTempBytes sizes what the running children hold under the temp root the
// adapter gave them. It is not cache: nothing reuses it, and it is the disk a
// scan actually fails on.
//
// Only the adapter's own root is read, never the shared temp directory, so
// every entry here is a scratch directory this process created: foreign
// directories can neither enter the total nor spend the budget, and the budget
// and deadline bound the walk whatever else shares the filesystem.
func trivyTempBytes(ctx context.Context, root string, remaining *int) (int64, error) {
	dir, err := os.Open(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No scan has run yet, or the root went with the process that owned
			// it. Either way the children hold nothing, and answering that
			// needs no budget: an exhausted one must not turn "no children"
			// into a failed sample.
			return 0, nil
		}
		return 0, err
	}
	// Listing the root costs an entry, like every other step of the walk, so an
	// exhausted budget fails this sample too instead of reporting a partial one.
	*remaining--
	if *remaining < 0 {
		return 0, errors.New("cache entry budget exceeded")
	}
	defer dir.Close()
	var total int64
	var partial error
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		entries, readErr := dir.ReadDir(256)
		for _, entry := range entries {
			path := filepath.Join(root, entry.Name())
			size, err := directoryBytes(ctx, path, remaining, skipUnsupported)
			var pathErr *fs.PathError
			if errors.As(err, &pathErr) && errors.Is(err, fs.ErrNotExist) {
				if pathErr.Path == path {
					// The whole directory went with the scan that owned it,
					// which is how these are supposed to end.
					continue
				}
				// Something inside it vanished mid-walk, so the total would be
				// short. Report no total rather than a wrong one.
				partial = err
				continue
			}
			if err != nil {
				return 0, err
			}
			total += size
		}
		if errors.Is(readErr, io.EOF) {
			return total, partial
		}
		if readErr != nil {
			return 0, readErr
		}
	}
}

// An extracted image layer legitimately contains symlinks, devices and sockets,
// which are not cache entries and must not fail the sample that meets them.
const (
	failOnUnsupported = false
	skipUnsupported   = true
)

// Walk one directory at a time without following symlinks or sorting/loading
// entire directories. The shared entry budget bounds memory and work per sample.
func directoryBytes(ctx context.Context, path string, remaining *int, skipUnsupportedEntries bool) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	*remaining--
	if *remaining < 0 {
		return 0, errors.New("cache entry budget exceeded")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if info.Mode().IsRegular() {
		return info.Size(), nil
	}
	if !info.IsDir() {
		if skipUnsupportedEntries {
			return 0, nil
		}
		return 0, fmt.Errorf("unsupported cache entry type: %s", info.Mode().Type())
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var total int64
	for {
		entries, readErr := f.ReadDir(128)
		for _, entry := range entries {
			n, err := directoryBytes(ctx, filepath.Join(path, entry.Name()), remaining, skipUnsupportedEntries)
			if err != nil {
				return 0, err
			}
			total += n
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return 0, readErr
		}
	}
}
