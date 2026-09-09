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
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
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
	acknowledgeScript = redis.NewScript(`
		if redis.call('GET', KEYS[4]) ~= ARGV[1] then return 0 end
		if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
		redis.call('XACK', KEYS[3], ARGV[2], ARGV[3])
		redis.call('XDEL', KEYS[3], ARGV[3])
		local ttl = tonumber(ARGV[4])
		if ttl > 0 then
			redis.call('PEXPIRE', KEYS[1], ttl)
			redis.call('PEXPIRE', KEYS[2], ttl)
		end
		redis.call('DEL', KEYS[4])
		return 1`)
	enqueueScript = redis.NewScript(`
		if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
		local delivery = redis.call('XADD', KEYS[2], '*', 'job', ARGV[2])
		local stored = redis.pcall('SET', KEYS[1], ARGV[1])
		if type(stored) == 'table' and stored.err then
			redis.call('XDEL', KEYS[2], delivery)
			return redis.error_reply(stored.err)
		end
		return 1`)
	// KEYS[1] scan job key, KEYS[2] scan report key; ARGV[1] job value, ARGV[2] TTL millis
	updateJobScript = redis.NewScript(`
		if ARGV[3] ~= '' and redis.call('GET', ARGV[3]) ~= ARGV[4] then return -1 end
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
		if ARGV[3] ~= '' and redis.call('GET', ARGV[3]) ~= ARGV[4] then return -1 end
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

func (s *store) Enqueue(ctx context.Context, scanJob job.ScanJob, stream string, payload []byte) (err error) {
	result := "success"
	defer s.operation("create", &err, &result)()
	scanJob.Durable = true
	value, rawSize, err := marshalSized(scanJob)
	if err != nil {
		return err
	}
	applied, err := enqueueScript.Run(ctx, s.rdb, []string{s.keyForScanJob(scanJob.Key), stream}, value, payload).Int()
	if err != nil {
		return err
	}
	if applied == 0 {
		result = "not_applied"
		return nil
	}
	s.written("job", rawSize, len(value))
	return nil
}

// Acknowledge starts report retention only when delivery is retired. A crash
// after storing the result but before XACK cannot expire the completion record
// and cause a recovered delivery to repeat an already completed scan.
func (s *store) Acknowledge(ctx context.Context, key job.ScanJobKey, stream, group, deliveryID string) (err error) {
	result := "success"
	defer s.operation("acknowledge", &err, &result)()
	state, err := s.getJob(ctx, key)
	if err != nil {
		return err
	}
	if state == nil || (state.Status != job.Finished && state.Status != job.Failed) {
		return xerrors.New("cannot acknowledge a non-terminal scan job")
	}
	lease := persistence.JobLease(ctx)
	if lease.Key == "" {
		return xerrors.New("acknowledgement requires job ownership")
	}
	ack, err := acknowledgeScript.Run(ctx, s.rdb,
		[]string{s.keyForScanJob(key), s.keyForScanReport(key), stream, lease.Key},
		lease.Token, group, deliveryID, s.ttlMillis()).Int()
	if err != nil {
		return err
	}
	if ack != 1 {
		return xerrors.New("scan job ownership lost before acknowledgement")
	}
	return nil
}

type store struct {
	metrics *metrics.Recorder
	cfg     etc.RedisStore
	rdb     *redis.Client
}

func NewStore(cfg etc.RedisStore, rdb *redis.Client, recorders ...*metrics.Recorder) persistence.Store {
	return &store{
		metrics: metrics.Optional(recorders),
		cfg:     cfg,
		rdb:     rdb,
	}
}

func (s *store) Create(ctx context.Context, scanJob job.ScanJob) (err error) {
	result := "success"
	defer s.operation("create", &err, &result)()
	value, rawSize, err := marshalSized(scanJob)
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

	applied, err := s.rdb.SetNX(ctx, key, value, s.cfg.ScanJobTTL).Result()
	if err != nil {
		return xerrors.Errorf("creating scan job: %w", err)
	}

	if applied {
		s.written("job", rawSize, len(value))
	} else {
		result = "not_applied"
	}
	return nil
}

// update rewrites the scan job key and re-arms the TTL on both keys so the
// report never outlives its job metadata.
func (s *store) update(ctx context.Context, scanJob job.ScanJob) error {
	value, rawSize, err := marshalSized(scanJob)
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

	lease := persistence.JobLease(ctx)
	ttl := s.ttlMillis()
	if scanJob.Durable {
		ttl = 0
	}
	applied, err := updateJobScript.Run(ctx, s.rdb,
		[]string{key, s.keyForScanReport(scanJob.Key)},
		value, ttl, lease.Key, lease.Token).Int()
	if err != nil {
		return xerrors.Errorf("updating scan job: %w", err)
	} else if applied == 0 {
		return missingJob(scanJob.Key)
	} else if applied == -1 {
		return xerrors.New("scan job ownership lost")
	}

	s.written("job", rawSize, len(value))
	return nil
}

func (s *store) Get(ctx context.Context, scanJobKey job.ScanJobKey) (resultJob *job.ScanJob, err error) {
	result := "success"
	defer s.operation("read", &err, &result)()
	defer func() {
		if err == nil && resultJob == nil {
			result = "not_found"
		}
	}()
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

func (s *store) UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, messages ...string) (err error) {
	result := "success"
	defer s.operation("status", &err, &result)()
	logger := storeLogger(scanJobKey)
	logger.Debug("Updating status for scan job", slog.String("new_status", newStatus.String()))

	scanJob, err := s.getJob(ctx, scanJobKey)
	if err != nil {
		return err
	}
	if scanJob == nil {
		return missingJob(scanJobKey)
	}

	scanJob.Status = newStatus
	if scanJob.Durable && newStatus == job.Pending {
		scanJob.Attempts++
	}
	scanJob.Error = ""
	if len(messages) > 0 {
		scanJob.Error = messages[0]
	}
	if newStatus == job.Finished {
		scanJob.FinishedAt = time.Now()
	}

	return s.update(ctx, *scanJob)
}

func (s *store) UpdateReport(ctx context.Context, scanJobKey job.ScanJobKey, report harbor.ScanReport) (err error) {
	result := "success"
	defer s.operation("report", &err, &result)()
	logger := storeLogger(scanJobKey)
	logger.Debug("Updating reports for scan job")

	value, rawSize, err := marshalSized(report)
	if err != nil {
		return xerrors.Errorf("marshaling scan report: %w", err)
	}

	state, err := s.getJob(ctx, scanJobKey)
	if err != nil {
		return err
	}
	if state == nil {
		return xerrors.Errorf("scan job (%s) not found", scanJobKey)
	}
	ttl := s.ttlMillis()
	if state.Durable {
		ttl = 0
	}
	lease := persistence.JobLease(ctx)
	applied, err := updateReportScript.Run(ctx, s.rdb,
		[]string{s.keyForScanJob(scanJobKey), s.keyForScanReport(scanJobKey)},
		value, ttl, lease.Key, lease.Token).Int()
	if err != nil {
		return xerrors.Errorf("updating scan report: %w", err)
	} else if applied == 0 {
		return missingJob(scanJobKey)
	} else if applied == -1 {
		return xerrors.New("scan job ownership lost")
	}

	s.written("report", rawSize, len(value))
	capability, format := metrics.JobLabels(scanJobKey)
	s.metrics.Observe("report_size_bytes", float64(rawSize), capability, format, "raw")
	s.metrics.Observe("report_size_bytes", float64(len(value)), capability, format, "compressed")
	return nil
}

func marshalSized(v any) ([]byte, int, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, 0, err
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err = gw.Write(data); err != nil {
		return nil, 0, xerrors.Errorf("compressing value: %w", err)
	}
	if err = gw.Close(); err != nil {
		return nil, 0, xerrors.Errorf("compressing value: %w", err)
	}
	return buf.Bytes(), len(data), nil
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

// Keep the public error text compatible while identifying missing records without
// guessing from error strings or asserting that they expired.
type missingJobError struct{ key job.ScanJobKey }

func (e missingJobError) Error() string {
	return fmt.Sprintf("scan job (%s) not found", e.key.String())
}
func missingJob(key job.ScanJobKey) error { return missingJobError{key} }

func (s *store) operation(op string, err *error, result *string) func() {
	started := time.Now()
	return func() {
		if *err != nil {
			*result = "error"
			var missing missingJobError
			if errors.As(*err, &missing) {
				*result = "not_found"
			}
		}
		s.metrics.Inc("store_operations_total", op, *result)
		s.metrics.Observe("store_operation_duration_seconds", time.Since(started).Seconds(), op)
	}
}

func (s *store) written(record string, raw, compressed int) {
	s.metrics.Add("store_bytes_written_total", float64(raw), record, "raw")
	s.metrics.Add("store_bytes_written_total", float64(compressed), record, "compressed")
}
