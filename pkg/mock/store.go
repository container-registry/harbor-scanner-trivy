package mock

import (
	"context"

	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/stretchr/testify/mock"
)

type Store struct {
	mock.Mock
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Enqueue(ctx context.Context, scanJob job.ScanJob, stream string, payload []byte) error {
	return s.Called(ctx, scanJob, stream, payload).Error(0)
}

func (s *Store) Acknowledge(ctx context.Context, key job.ScanJobKey, stream, group, deliveryID string) error {
	return s.Called(ctx, key, stream, group, deliveryID).Error(0)
}

func (s *Store) Create(ctx context.Context, scanJob job.ScanJob) error {
	args := s.Called(ctx, scanJob)
	return args.Error(0)
}

func (s *Store) Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error) {
	args := s.Called(ctx, scanJobKey)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

func (s *Store) UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, error ...string) error {
	args := s.Called(ctx, scanJobKey, newStatus, error)
	return args.Error(0)
}

func (s *Store) UpdateReport(ctx context.Context, scanJobKey job.ScanJobKey, report harbor.ScanReport) error {
	args := s.Called(ctx, scanJobKey, report)
	return args.Error(0)
}
