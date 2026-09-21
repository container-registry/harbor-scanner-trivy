# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Harbor Scanner Adapter for Trivy is a Go service that runs Trivy scans for Harbor. It implements Harbor's scanner adapter API: HTTP requests enter a Redis-backed job queue, workers execute scans, and Harbor retrieves vulnerability reports or SBOMs. Harbor >= 2.2 uses this adapter as its default scanner.

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
task docs:svgbob        # Regenerate Kroki links for SVGBob diagrams in markdown (diagram in HTML comment, link follows)
```

Tool and base-image pins live in `versions.env` (loaded by Taskfile via dotenv).
Chart tasks live in `taskfile/helm.yml`, included under the `helm:` namespace.

Releases are automated with release-please. The adapter (`vX.Y.Z`) and Helm chart (`chart-vX.Y.Z`) have independent release
lines, each with its own config, manifest and changelog. Never push `v*` or `chart-v*` tags
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

Request flow:
1. `POST /api/v1/scan` -> API handler validates request -> Enqueuer atomically creates queued state and a Redis Stream delivery -> returns 202 with job ID
2. One worker per pod claims a stream delivery with a renewable lease -> Controller executes Trivy CLI as a cancellable subprocess -> transforms JSON output to Harbor report format -> stores result in Redis -> acknowledges delivery and starts report retention
3. `GET /api/v1/scan/{id}/report` -> returns 302 (still processing) or the finished report

Packages:
- `cmd/scanner-trivy/`: entry point, wires all components together
- `pkg/http/api/v1/`: HTTP handler implementing Harbor scanner adapter API (scan, report, metadata, probes)
- `pkg/scan/`: controller (orchestrates scan execution) and transformer (Trivy output -> Harbor report)
- `pkg/trivy/`: wrapper around Trivy CLI (`trivy image` subprocess), model types for Trivy JSON output
- `pkg/queue/`: Redis Streams consumer group, renewable fenced ownership and recovery; requires Redis 6.2+ or compatible Valkey
- `pkg/persistence/redis/`: atomic enqueue/acknowledgement and fenced job/report writes; queued work persists, completed reports have a configurable TTL
- `pkg/etc/`: configuration via environment variables (all prefixed `SCANNER_`), parsed with `caarlos0/env/v6`
- `pkg/harbor/`: Harbor domain models (ScanRequest, ScanReport, Severity, etc.)
- `pkg/mock/`: testify mocks for interfaces
- `deploy/chart/`: the Helm chart: `values.schema.json` closes the
  root so unknown keys fail the render, `templates/validate-values.yaml` holds the
  cross-field guards a schema cannot express, `tests/` is a helm-unittest suite,
  and `ci/` + `example/` are values scenarios CI renders on every change

API endpoints:
- `POST /api/v1/scan`: submit scan request
- `GET /api/v1/scan/{scan_request_id}/report`: retrieve scan report
- `GET /api/v1/metadata`: adapter metadata and capabilities
- `GET /probe/healthy`, `GET /probe/ready`: health probes
- `GET /metrics`: Prometheus metrics

## Key Design Decisions

- The binary shells out to the `trivy` CLI rather than using Trivy as a library. The Trivy binary must be available in PATH (the Docker image inherits from `aquasec/trivy`).
- All configuration is via environment variables prefixed with `SCANNER_`. No config files.
- Redis is the sole persistence and job queue backend (Streams for queue, key-value for job state). Delivery is at least once; never trim unacknowledged jobs or evict operational keys. Drain before upgrading from Pub/Sub releases (see docs/SCALING.md).
- Scale with one worker per pod, separate writable local DB volumes, and a dedicated shared Redis/Valkey analysis-cache instance. The adapter forwards `SCANNER_TRIVY_CACHE_*` to Trivy; Redis cache credentials go through the child environment, never command arguments. This cache connection is separate from the job/report connection.
- `go.mod` has a `replace` directive: `google/go-containerregistry` is replaced with a fork (`knqyf263/go-containerregistry`) for custom registry auth handling.
- Version info (`version`, `commit`, `date`) is injected via ldflags at build time by `task build`.
- The chart generates nothing at render time (no `randAlphaNum`), so GitOps
  engines see no drift; every credential has an `existingSecret` form. CI proves
  it by rendering `ci/gitops-values.yaml` twice and diffing.
- Adding a value means touching four places: `values.yaml` (with a `# --`
  helm-docs comment), `values.schema.json`, a test in `tests/`, and the README
  via `task helm:docs`. `task helm:lint:schema` fails on drift between the first
  two.
