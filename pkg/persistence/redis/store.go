package redis

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence"
	redis "github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"
)

// Job and report writes must be conditional on the job key still existing and
// re-arm both TTLs together, or a scan job expiring mid-update leaves either a
// silently dropped status change (SET XX no-op) or an orphaned report blob.
// Lua gives us that atomically; both keys always live on one instance because
// the adapter only ever connects via a non-cluster client (see pkg/redisx).
// A TTL of 0 must mean "no expiry", mirroring how go-redis treats a zero
// expiration on SET (and how pre-split versions behaved).
var (
	// KEYS[1] scan job key, KEYS[2] scan report key; ARGV[1] job value, ARGV[2] TTL millis
	updateJobScript = redis.NewScript(`
		if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
		local ttl = tonumber(ARGV[2])
		if ttl == 0 then
			redis.call('SET', KEYS[1], ARGV[1])
			redis.call('PERSIST', KEYS[2])
		else
			redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl)
			redis.call('PEXPIRE', KEYS[2], ttl)
		end
		return 1`)

	// KEYS[1] scan job key, KEYS[2] scan report key; ARGV[1] report value, ARGV[2] TTL millis
	updateReportScript = redis.NewScript(`
		if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
		local ttl = tonumber(ARGV[2])
		if ttl == 0 then
			redis.call('SET', KEYS[2], ARGV[1])
			redis.call('PERSIST', KEYS[1])
		else
			redis.call('SET', KEYS[2], ARGV[1], 'PX', ttl)
			redis.call('PEXPIRE', KEYS[1], ttl)
		end
		return 1`)
)

type store struct {
	cfg etc.RedisStore
	rdb *redis.Client
}

func NewStore(cfg etc.RedisStore, rdb *redis.Client) persistence.Store {
	return &store{
		cfg: cfg,
		rdb: rdb,
	}
}

func (s *store) Create(ctx context.Context, scanJob job.ScanJob) error {
	value, err := marshalCompressed(scanJob)
	if err != nil {
		return xerrors.Errorf("marshaling scan job: %w", err)
	}

	key := s.keyForScanJob(scanJob.Key)

	logger := storeLogger(scanJob.Key)
	logger.Debug("Saving scan job",
		slog.String("scan_job_status", scanJob.Status.String()),
		slog.String("redis_key", key),
		slog.Duration("expire", s.cfg.ScanJobTTL),
	)

	if err = s.rdb.SetNX(ctx, key, value, s.cfg.ScanJobTTL).Err(); err != nil {
		return xerrors.Errorf("creating scan job: %w", err)
	}

	return nil
}

// update rewrites the scan job key and re-arms the TTL on both keys so the
// report never outlives its job metadata.
func (s *store) update(ctx context.Context, scanJob job.ScanJob) error {
	value, err := marshalCompressed(scanJob)
	if err != nil {
		return xerrors.Errorf("marshaling scan job: %w", err)
	}

	key := s.keyForScanJob(scanJob.Key)

	logger := storeLogger(scanJob.Key)
	logger.Debug("Updating scan job",
		slog.String("scan_job_status", scanJob.Status.String()),
		slog.String("redis_key", key),
		slog.Duration("expire", s.cfg.ScanJobTTL),
	)

	applied, err := updateJobScript.Run(ctx, s.rdb,
		[]string{key, s.keyForScanReport(scanJob.Key)},
		value, s.ttlMillis()).Int()
	if err != nil {
		return xerrors.Errorf("updating scan job: %w", err)
	} else if applied == 0 {
		return xerrors.Errorf("scan job (%s) not found", scanJob.Key)
	}

	return nil
}

func (s *store) Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error) {
	scanJob, err := s.getJob(ctx, scanJobKey)
	if scanJob == nil || err != nil {
		return scanJob, err
	}

	value, err := s.rdb.Get(ctx, s.keyForScanReport(scanJobKey)).Result()
	if errors.Is(err, redis.Nil) {
		// No separate report key: either the scan has not finished yet, or the
		// value predates the key split and carries the report inline.
		return scanJob, nil
	} else if err != nil {
		return nil, err
	}

	data, err := decompress([]byte(value))
	if err != nil {
		return nil, xerrors.Errorf("decompressing scan report: %w", err)
	}

	// Reset first: unmarshaling merges into non-zero fields, which would leak
	// remnants of an inline pre-split report into the fresh one.
	scanJob.Report = harbor.ScanReport{}
	if err = json.Unmarshal(data, &scanJob.Report); err != nil {
		return nil, xerrors.Errorf("unmarshaling scan report: %w", err)
	}

	return scanJob, nil
}

// getJob reads only the scan job key, never the report blob. Values written
// before the key split may carry the report inline; it is preserved untouched
// through update round-trips.
func (s *store) getJob(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error) {
	key := s.keyForScanJob(scanJobKey)
	value, err := s.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	data, err := decompress([]byte(value))
	if err != nil {
		return nil, xerrors.Errorf("decompressing scan job: %w", err)
	}

	var scanJob job.ScanJob
	if err = json.Unmarshal(data, &scanJob); err != nil {
		return nil, xerrors.Errorf("unmarshaling scan job: %w", err)
	}

	return &scanJob, nil
}

func (s *store) UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, error ...string) error {
	logger := storeLogger(scanJobKey)
	logger.Debug("Updating status for scan job", slog.String("new_status", newStatus.String()))

	scanJob, err := s.getJob(ctx, scanJobKey)
	if scanJob == nil {
		return xerrors.Errorf("scan job (%s) not found", scanJobKey)
	} else if err != nil {
		return err
	}

	scanJob.Status = newStatus
	if len(error) > 0 {
		scanJob.Error = error[0]
	}

	return s.update(ctx, *scanJob)
}

func (s *store) UpdateReport(ctx context.Context, scanJobKey job.ScanJobKey, report harbor.ScanReport) error {
	logger := storeLogger(scanJobKey)
	logger.Debug("Updating reports for scan job")

	value, err := marshalCompressed(report)
	if err != nil {
		return xerrors.Errorf("marshaling scan report: %w", err)
	}

	applied, err := updateReportScript.Run(ctx, s.rdb,
		[]string{s.keyForScanJob(scanJobKey), s.keyForScanReport(scanJobKey)},
		value, s.ttlMillis()).Int()
	if err != nil {
		return xerrors.Errorf("updating scan report: %w", err)
	} else if applied == 0 {
		return xerrors.Errorf("scan job (%s) not found", scanJobKey)
	}

	return nil
}

func marshalCompressed(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err = gw.Write(data); err != nil {
		return nil, xerrors.Errorf("compressing value: %w", err)
	}
	if err = gw.Close(); err != nil {
		return nil, xerrors.Errorf("compressing value: %w", err)
	}
	return buf.Bytes(), nil
}

// maxDecompressedSize guards against decompression bombs planted by a
// compromised Redis. Reads allocate up to this much before rejecting, so it
// must stay well below the adapter's memory sizing (Helm suggests a 512Mi
// request); 64 MiB is ~28x the largest report observed in production.
const maxDecompressedSize = 64 << 20

// decompress gunzips value if it carries the gzip magic header. JSON cannot
// start with 0x1f, so values written by older, non-compressing versions pass
// through unchanged during a rolling upgrade.
func decompress(value []byte) ([]byte, error) {
	if len(value) < 2 || value[0] != 0x1f || value[1] != 0x8b {
		return value, nil
	}

	gr, err := gzip.NewReader(bytes.NewReader(value))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	data, err := io.ReadAll(io.LimitReader(gr, maxDecompressedSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDecompressedSize {
		return nil, xerrors.Errorf("decompressed value exceeds %d bytes", maxDecompressedSize)
	}
	return data, nil
}

// ttlMillis converts ScanJobTTL for the Lua scripts. Sub-millisecond positive
// durations round up to 1ms because PX 0 is a Redis error, while an exact 0
// keeps its go-redis meaning of "no expiry" (handled in the scripts).
func (s *store) ttlMillis() int64 {
	ms := s.cfg.ScanJobTTL.Milliseconds()
	if ms == 0 && s.cfg.ScanJobTTL > 0 {
		return 1
	}
	return ms
}

func (s *store) keyForScanJob(scanJobKey job.ScanJobKey) string {
	return fmt.Sprintf("%s:scan-job:%s", s.cfg.Namespace, scanJobKey.String())
}

func (s *store) keyForScanReport(scanJobKey job.ScanJobKey) string {
	return fmt.Sprintf("%s:scan-report:%s", s.cfg.Namespace, scanJobKey.String())
}

func storeLogger(scanJobKey job.ScanJobKey) *slog.Logger {
	return slog.With(
		slog.String("scan_job_id", scanJobKey.ID),
		slog.String("mime_type", scanJobKey.MIMEType.String()))
}
