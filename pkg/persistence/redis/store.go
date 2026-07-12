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
		return err
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

func (s *store) update(ctx context.Context, scanJob job.ScanJob) error {
	value, err := marshalCompressed(scanJob)
	if err != nil {
		return err
	}

	key := s.keyForScanJob(scanJob.Key)

	logger := storeLogger(scanJob.Key)
	logger.Debug("Updating scan job",
		slog.String("scan_job_status", scanJob.Status.String()),
		slog.String("redis_key", key),
		slog.Duration("expire", s.cfg.ScanJobTTL),
	)

	if err = s.rdb.SetXX(ctx, key, value, s.cfg.ScanJobTTL).Err(); err != nil {
		return xerrors.Errorf("updating scan job: %w", err)
	}

	return nil
}

func (s *store) Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error) {
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

	scanJob, err := s.Get(ctx, scanJobKey)
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

	scanJob, err := s.Get(ctx, scanJobKey)
	if err != nil {
		return err
	} else if scanJob == nil {
		return xerrors.Errorf("scan job (%s) not found", scanJobKey)
	}

	scanJob.Report = report
	return s.update(ctx, *scanJob)
}

func marshalCompressed(scanJob job.ScanJob) ([]byte, error) {
	data, err := json.Marshal(scanJob)
	if err != nil {
		return nil, xerrors.Errorf("marshaling scan job: %w", err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err = gw.Write(data); err != nil {
		return nil, xerrors.Errorf("compressing scan job: %w", err)
	}
	if err = gw.Close(); err != nil {
		return nil, xerrors.Errorf("compressing scan job: %w", err)
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

func (s *store) keyForScanJob(scanJobKey job.ScanJobKey) string {
	return fmt.Sprintf("%s:scan-job:%s", s.cfg.Namespace, scanJobKey.String())
}

func storeLogger(scanJobKey job.ScanJobKey) *slog.Logger {
	return slog.With(
		slog.String("scan_job_id", scanJobKey.ID),
		slog.String("mime_type", scanJobKey.MIMEType.String()))
}
