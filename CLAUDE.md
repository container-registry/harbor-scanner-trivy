# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Harbor Scanner Adapter for Trivy -- a Go microservice that integrates the Trivy vulnerability scanner with Harbor container registry. It implements Harbor's scanner adapter API, accepting async scan requests via HTTP, processing them through a Redis-backed job queue, and returning vulnerability/SBOM reports. This is the default scanner in Harbor >= 2.2.

Module: `github.com/container-registry/harbor-scanner-trivy`

## Build & Test Commands

```bash
task build              # Build binary for native arch (CI: linux/amd64,linux/arm64)
task test               # Unit tests with race detection and coverage
task test:integration   # Integration tests (build tag: integration, uses testcontainers)
task test:component     # Component tests (build tag: component, requires Docker)
task lint               # golangci-lint (Docker); task lint:local uses a pinned binary
task image:local        # Build local Docker image (harbor-scanner-trivy:<version>)
task run                # Run locally with debug logging on :8080
task helm:ci            # Full Helm chart quality gate (what chart-ci.yml runs)
task helm:unittest      # helm unittest only
task helm:docs          # Regenerate the chart README from values.yaml
```

Tool and base-image pins live in `versions.env` (loaded by Taskfile via dotenv).
Chart tasks live in `taskfile/helm.yml`, included under the `helm:` namespace.

Releases are automated with release-please. There are **two independent release
lines** - the adapter (`vX.Y.Z`) and the Helm chart (`chart-vX.Y.Z`), each with
its own config, manifest and changelog. Never push `v*` or `chart-v*` tags
manually (see docs/RELEASES.md).

Run a single test:
```bash
go test -v -run TestFunctionName ./pkg/scan/...
```

Run a single integration test:
```bash
go test -v -tags=integration -run TestName ./test/integration/...
```

## Architecture

**Request flow:**
1. `POST /api/v1/scan` -> API handler validates request -> Enqueuer creates job in Redis (status: Queued) -> returns 202 with job ID
2. Worker (subscribes to Redis Pub/Sub channel) picks up job -> Controller executes Trivy CLI as subprocess -> transforms JSON output to Harbor report format -> stores result in Redis
3. `GET /api/v1/scan/{id}/report` -> returns 302 (still processing) or the finished report

**Key packages:**
- `cmd/scanner-trivy/` -- entry point, wires all components together
- `pkg/http/api/v1/` -- HTTP handler implementing Harbor scanner adapter API (scan, report, metadata, probes)
- `pkg/scan/` -- controller (orchestrates scan execution) and transformer (Trivy output -> Harbor report)
- `pkg/trivy/` -- wrapper around Trivy CLI (`trivy image` subprocess), model types for Trivy JSON output
- `pkg/queue/` -- Redis Pub/Sub job queue: enqueuer submits jobs, worker processes them with distributed locking
- `pkg/persistence/redis/` -- stores scan jobs and reports in Redis with configurable TTL
- `pkg/etc/` -- configuration via environment variables (all prefixed `SCANNER_`), parsed with `caarlos0/env/v6`
- `pkg/harbor/` -- Harbor domain models (ScanRequest, ScanReport, Severity, etc.)
- `pkg/mock/` -- testify mocks for interfaces
- `helm/harbor-scanner-trivy/` -- the Helm chart: `values.schema.json` closes the
  root so unknown keys fail the render, `templates/validate-values.yaml` holds the
  cross-field guards a schema cannot express, `tests/` is a helm-unittest suite,
  and `ci/` + `example/` are values scenarios CI renders on every change

**API endpoints:**
- `POST /api/v1/scan` -- submit scan request
- `GET /api/v1/scan/{scan_request_id}/report` -- retrieve scan report
- `GET /api/v1/metadata` -- adapter metadata and capabilities
- `GET /probe/healthy`, `GET /probe/ready` -- health probes
- `GET /metrics` -- Prometheus metrics

## Key Design Decisions

- The binary shells out to the `trivy` CLI rather than using Trivy as a library. The Trivy binary must be available in PATH (the Docker image inherits from `aquasec/trivy`).
- All configuration is via environment variables prefixed with `SCANNER_`. No config files.
- Redis is the sole persistence and job queue backend (Pub/Sub for queue, key-value for job state).
- `go.mod` has a `replace` directive: `google/go-containerregistry` is replaced with a fork (`knqyf263/go-containerregistry`) for custom registry auth handling.
- Version info (`version`, `commit`, `date`) is injected via ldflags at build time by `task build`.
- The chart generates nothing at render time (no `randAlphaNum`), so GitOps
  engines see no drift; every credential has an `existingSecret` form. CI proves
  it by rendering `ci/gitops-values.yaml` twice and diffing.
- Adding a value means touching four places: `values.yaml` (with a `# --`
  helm-docs comment), `values.schema.json`, a test in `tests/`, and the README
  via `task helm:docs`. `task helm:lint:schema` fails on drift between the first
  two.
