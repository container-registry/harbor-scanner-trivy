package queue

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"

	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence"
)

const scanArtifactJobName = "scan_artifact"

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type enqueuer struct {
	metrics   *metrics.Recorder
	namespace string
	store     persistence.Store
}

type Job struct {
	EnqueuedAt time.Time `json:"enqueued_at,omitzero"`
	Name       string
	Key        job.ScanJobKey
	Args       Args
}

func (s *Job) ID() string {
	return s.Key.String()
}

type Args struct {
	ScanRequest *harbor.ScanRequest `json:",omitempty"`
}

func NewEnqueuer(config etc.JobQueue, rdb *redis.Client, store persistence.Store, recorders ...*metrics.Recorder) Enqueuer {
	return &enqueuer{
		metrics:   metrics.Optional(recorders),
		namespace: config.Namespace,
		store:     store,
	}
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	if len(request.Capabilities) == 0 {
		return "", xerrors.Errorf("no capabilities provided")
	}

	jobID := makeIdentifier()

	for _, c := range request.Capabilities {
		if c.Type == harbor.CapabilityTypeVulnerability {
			c.Parameters = &harbor.CapabilityAttributes{
				SBOMMediaTypes: []api.MediaType{""},
			}
		}

		for _, mediaType := range lo.FromPtr(c.Parameters).SBOMMediaTypes {
			for _, m := range c.ProducesMIMETypes {
				jobKey := job.ScanJobKey{
					ID:        jobID,
					MIMEType:  m,
					MediaType: mediaType,
				}

				j := Job{
					EnqueuedAt: time.Now(),
					Name:       scanArtifactJobName,
					Key:        jobKey,
					Args: Args{
						ScanRequest: &request,
					},
				}
				scanJob := job.ScanJob{
					Key:    jobKey,
					Status: job.Queued,
				}

				if err := e.enqueue(ctx, j, scanJob); err != nil {
					return "", xerrors.Errorf("enqueuing scan job: %v", err)
				}
			}
		}
	}

	return jobID, nil
}

func (e *enqueuer) enqueue(ctx context.Context, j Job, scanJob job.ScanJob) error {
	logger := slog.With(slog.String("job_id", j.Key.ID), slog.String("mime_type", j.Key.MIMEType.String()))
	logger.Debug("Enqueueing scan job")

	b, err := json.Marshal(j)
	if err != nil {
		return xerrors.Errorf("marshaling scan request: %v", err)
	}

	// Persist both state and delivery before acknowledging the Harbor request.
	if err = e.store.Enqueue(ctx, scanJob, redisJobStream(e.namespace), b); err != nil {
		return xerrors.Errorf("enqueuing scan artifact job: %v", err)
	}

	capability, format := metrics.JobLabels(j.Key)
	e.metrics.Inc("jobs_enqueued_total", capability, format)
	logger.Debug("Successfully enqueued scan job")
	return nil
}

func makeIdentifier() string {
	b := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func redisJobStream(namespace string) string {
	return namespace + ":stream:v1:" + scanArtifactJobName
}
