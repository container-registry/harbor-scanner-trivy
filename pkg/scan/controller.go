package scan

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/container-registry/harbor-scanner-trivy/pkg/harbor"
	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
	"github.com/container-registry/harbor-scanner-trivy/pkg/persistence"
	"github.com/container-registry/harbor-scanner-trivy/pkg/trivy"
)

type Controller interface {
	Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error
}

type controller struct {
	metrics     *metrics.Recorder
	store       persistence.Store
	wrapper     trivy.Wrapper
	transformer Transformer
}

// A storage interruption must leave the stream delivery pending for recovery,
// rather than turn a successfully scanned image into a permanent failure.
type persistenceError struct{ error }

func (e *persistenceError) Unwrap() error { return e.error }

func NewController(store persistence.Store, wrapper trivy.Wrapper, transformer Transformer, recorders ...*metrics.Recorder) Controller {
	return &controller{
		metrics:     metrics.Optional(recorders),
		store:       store,
		wrapper:     wrapper,
		transformer: transformer,
	}
}

func (c *controller) Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error {
	stage := "internal"
	finish := c.metrics.BeginExecution(scanJobKey)
	processingErr := c.scan(ctx, scanJobKey, request, &stage)
	defer func() { finish(processingErr == nil, stage, failureCategory(processingErr, stage)) }()
	if err := processingErr; err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var storeErr *persistenceError
		if errors.As(err, &storeErr) {
			return err
		}
		errMsg := err.Error()
		var scanErr *trivy.ScanError
		if errors.As(err, &scanErr) {
			if scanErr.Category == trivy.ErrCategoryCache {
				return err
			}
			slog.Error("Scan failed",
				slog.String("category", string(scanErr.Category)),
				slog.String("image_ref", scanErr.ImageRef),
				slog.String("detail", scanErr.Detail),
			)
			errMsg = fmt.Sprintf("[%s] %s", scanErr.Category, scanErr.Detail)
		} else {
			slog.Error("Scan failed", slog.String("err", errMsg))
		}
		if err = c.store.UpdateStatus(ctx, scanJobKey, job.Failed, errMsg); err != nil {
			return xerrors.Errorf("updating scan job as failed: %w", err)
		}
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobKey job.ScanJobKey, req *harbor.ScanRequest, stage *string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			*stage = "internal"
			if recovered, ok := r.(error); ok {
				err = recovered
			} else {
				err = fmt.Errorf("scan panic: %v", r)
			}
		}
	}()

	*stage = "status"
	err = c.store.UpdateStatus(ctx, scanJobKey, job.Pending)
	if err != nil {
		return &persistenceError{xerrors.Errorf("updating scan job status: %w", err)}
	}

	*stage = "target"
	imageRef, nonSSL, err := req.GetImageRef()
	if err != nil {
		return err
	}

	*stage = "auth"
	auth, err := c.ToRegistryAuth(req.Registry.Authorization)
	if err != nil {
		return err
	}

	ref := trivy.ImageRef{
		Name:   imageRef,
		Auth:   auth,
		NonSSL: nonSSL,
	}

	*stage = "scan"
	scanReport, err := c.wrapper.Scan(ref, trivy.ScanOption{
		Format:  determineFormat(scanJobKey.MediaType),
		Context: ctx,
	})
	if err != nil {
		return xerrors.Errorf("running trivy wrapper: %w", err)
	}

	*stage = "transform"
	harborScanReport := c.transformer.Transform(scanJobKey.MediaType, lo.FromPtr(req), scanReport)
	*stage = "report"
	if err = c.store.UpdateReport(ctx, scanJobKey, harborScanReport); err != nil {
		return &persistenceError{xerrors.Errorf("saving scan report: %w", err)}
	}

	*stage = "status"
	if err = c.store.UpdateStatus(ctx, scanJobKey, job.Finished); err != nil {
		return &persistenceError{xerrors.Errorf("updating scan job status: %w", err)}
	}

	return
}

func (c *controller) ToRegistryAuth(authorization string) (auth trivy.RegistryAuth, err error) {
	if authorization == "" {
		return trivy.NoAuth{}, nil
	}

	tokens := strings.Split(authorization, " ")
	if len(tokens) != 2 {
		return auth, xerrors.Errorf("parsing authorization: expected <type> <credentials> got %s", authorization)
	}

	switch tokens[0] {
	case "Basic":
		return c.decodeBasicAuth(tokens[1])
	case "Bearer":
		return trivy.BearerAuth{
			Token: tokens[1],
		}, nil
	}

	return auth, xerrors.Errorf("unrecognized authorization type: %s", tokens[0])
}

func (c *controller) decodeBasicAuth(value string) (auth trivy.RegistryAuth, err error) {
	creds, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return auth, err
	}
	tokens := strings.Split(string(creds), ":")
	auth = trivy.BasicAuth{
		Username: tokens[0],
		Password: tokens[1],
	}
	return
}

func determineFormat(m api.MediaType) trivy.Format {
	switch m {
	case api.MediaTypeSPDX:
		return trivy.FormatSPDX
	case api.MediaTypeCycloneDX:
		return trivy.FormatCycloneDX
	default:
		return trivy.FormatJSON
	}
}

func failureCategory(err error, stage string) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, syscall.ENOSPC) {
		return "storage_full"
	}
	if errors.Is(err, syscall.EIO) {
		return "storage_io"
	}
	var scanErr *trivy.ScanError
	if errors.As(err, &scanErr) {
		return string(scanErr.Category)
	}
	if stage == "status" || stage == "report" {
		return "persistence"
	}
	if stage == "auth" {
		return "auth"
	}
	if stage == "internal" || stage == "transform" {
		return "internal"
	}
	return "unknown"
}
