package persistence

import (
	"context"

	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
)

type Store interface {
	// Enqueue atomically persists a queued job and its stream delivery.
	Enqueue(ctx context.Context, scanJob job.ScanJob, stream string, payload []byte) error
	Acknowledge(ctx context.Context, key job.ScanJobKey, stream, group, deliveryID string) error
	Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error)
	// Mutations require the current worker lease, carried by WithLease.
	UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, error ...string) error
	UpdateReport(ctx context.Context, scanJobKey job.ScanJobKey, report harbor.ScanReport) error
}

type leaseKey struct{}

type Lease struct{ Key, Token string }

// WithLease fences job writes when a worker loses ownership during a partition.
func WithLease(ctx context.Context, key, token string) context.Context {
	return context.WithValue(ctx, leaseKey{}, Lease{Key: key, Token: token})
}

func JobLease(ctx context.Context) Lease {
	lease, _ := ctx.Value(leaseKey{}).(Lease)
	return lease
}
