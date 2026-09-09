package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
)

type databaseMetadata struct {
	Version                             int
	UpdatedAt, NextUpdate, DownloadedAt time.Time
}

// Start samples metadata and filesystems in one bounded background loop. The
// returned function waits for cancellation/collection completion before shutdown.
func (r *Recorder) Start(ctx context.Context, cfg etc.Config, adapterVersion string) func() {
	if r == nil {
		return func() {}
	}
	r.Set("worker_concurrency", float64(cfg.JobQueue.WorkerConcurrency))
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
			if version == "" {
				versionCtx, stop := context.WithTimeout(ctx, cfg.Metrics.CollectionTimeout)
				cmd := exec.CommandContext(versionCtx, "trivy", "--cache-dir", cfg.Trivy.CacheDir, "version", "--format", "json")
				output, err := r.Run("version", cmd, runLimited)
				stop()
				var info struct{ Version string }
				if err == nil && json.Unmarshal(output, &info) == nil && info.Version != "" {
					version = info.Version
					r.Set("build_info", 1, adapterVersion, version)
				}
			}
			r.collectMetadata(cfg.Trivy, version != "")
			r.collectFilesystem(cfg.Trivy.CacheDir, "cache")
			r.collectFilesystem(cfg.Trivy.ReportsDir, "reports")
			if cfg.Metrics.CacheSizeEnabled {
				walkCtx, stop := context.WithTimeout(ctx, cfg.Metrics.CollectionTimeout)
				r.collectCache(walkCtx, cfg.Trivy.CacheDir, cfg.Metrics.CacheMaxFiles)
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

// Limit command output even if a broken binary emits unbounded data.
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, errors.New("metadata output exceeds 1 MiB")
	}
	return b.Buffer.Write(p)
}

func runLimited(cmd *exec.Cmd) ([]byte, error) {
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return output.Bytes(), err
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
		failed := (fileErr != nil && !errors.Is(fileErr, fs.ErrNotExist)) || (err != nil && !errors.Is(err, fs.ErrNotExist))
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

func (r *Recorder) collectCache(ctx context.Context, root string, maxFiles int) {
	started := time.Now()
	remaining := maxFiles
	var firstErr error
	for _, part := range []struct{ kind, dir string }{{"analysis", "fanal"}, {"vulnerability_db", "db"}, {"java_db", "java-db"}} {
		size, err := directoryBytes(ctx, filepath.Join(root, part.dir), &remaining)
		if err != nil {
			r.Delete("cache_size_bytes", part.kind)
			firstErr = err
		} else {
			r.Set("cache_size_bytes", float64(size), part.kind)
		}
	}
	r.collectionResult("cache_size", started, firstErr)
}

// Walk one directory at a time without following symlinks or sorting/loading
// entire directories. The shared entry budget bounds memory and work per sample.
func directoryBytes(ctx context.Context, path string, remaining *int) (int64, error) {
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
			n, err := directoryBytes(ctx, filepath.Join(path, entry.Name()), remaining)
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
