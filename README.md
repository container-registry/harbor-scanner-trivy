[![GitHub Release][release-img]][release]
[![License][license-img]][license]

# Harbor Scanner Adapter for Trivy

[Trivy] as a [Harbor] scanner: vulnerability reports and SBOMs for every image Harbor stores, shown in the Harbor
UI and API. A drop-in for the adapter Harbor bundles, built for registries that scan thousands of artifacts at a
time.

Maintained by [container-registry.com], forked from [goharbor/harbor-scanner-trivy].

<img src="docs/images/vulnerabilities.png" alt="Vulnerability report in the Harbor UI" width="720">

## Contents

- [What it is](#what-it-is)
- [How it works](#how-it-works)
- [What it offers](#what-it-offers)
- [Install](#install)
- [Releases](#releases)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Contributing](#contributing)

## What it is

Harbor does not scan images itself. It talks to a scanner through its scanner adapter API, and this service is the
adapter for Trivy: it accepts Harbor's scan requests, runs Trivy, and returns the results in the format Harbor
renders. Harbor >= 2.2 ships the upstream version of this adapter as its default scanner.

This fork keeps the same API, report format and findings, and adds what running Harbor as a service demanded:
predictable Redis memory under bulk scans, faster "Scan All" runs, a Trivy binary we can patch, and signed releases
that follow Trivy's cadence instead of Harbor's. Upstream commits are cherry-picked into this fork twice a day by
[an automated workflow](.github/workflows/upstream-cherry-pick.yml).

## How it works

<!--
```SVGBob
┌──────────┐ "POST /api/v1/scan"      ┌───────────────┐   "enqueue job"    ┌─────────────┐   "dequeue job"   ┌────────────────┐
│          │─────────────────────────▶│               │───────────────────▶│             │──────────────────▶│  "Adapter"     │
│ "Harbor" │ "202 + job id"           │  "Adapter"    │                    │   "Redis"   │                   │  "worker"      │
│          │◀─────────────────────────│  "API :8080"  │                    │ "job queue" │   "store report"  │                │
│          │                          │               │   "read report"    │  "reports"  │◀──────────────────│ "trivy image"  │
│          │ "GET .../{id}/report"    │               │◀───────────────────│             │                   │    "<ref>"     │
│          │─────────────────────────▶│               │                    └─────────────┘                   └───────┬────────┘
│          │◀─────────────────────────│               │                                                              │
└──────────┘ "302 while running,"     └───────────────┘                                        "pull image layers,"  │
             "then the report"                                                                 "refresh Trivy DB"    ▼
                                                                                             ┌──────────────────────────────┐
                                                                                             │  "Registry"      "ghcr.io"   │
                                                                                             └──────────────────────────────┘
```
-->
![Diagram](https://kroki.io/svgbob/svg/eNq9VcFOg0AQvfsVk7naQK2XxhgTjUY92Wh_YFu2sIqAC7RpjEnTswcPpO1HePbk1_AlwgKtFGhLEScbkt3svpl5M4_xvXffm2xcH4Cdu4cuyMRi8vBItvvEQBDmb3-dAQNAary41KXwaPawLIwAUGgKoHwYIdCB701hacGmPEbxmn2l0Ku7yALuDxdj4blCLIdyTOAEI3hDeM8MDsWm1WzBYcgzMAXTztcAsvmuLgLeU4XZWHgtghuZ_CkJZxlPKt_55C-LFOXQuYWTdrPdxI05YMiB6DpMcrIdk1Pg1DK5k_84LwcotNyOCR1xSpSVn4St6MDGqswEuTmcDcfAnolKsSBqvL7qgiRJ8itT3uT1YDKNOa9YFtjGWXyKp5wOzrC4Y-rXdH4pvZ2BF6Xef24A-g-97JL97haVzNtOER4HP6KRxvRAcK5hMENtYGmmi_nONbRcXY9UAToZU243YnWkrzkaNSD4_JZoJQukPeDU1qArdHl5EQlt9n0AddpeY7TMwK05-qmYMyqzHT6Oi4Cq1ucSM-PJU3cEXp38LX4AVaUSjA==)

1. Harbor posts a scan request with the artifact reference and a pull credential. The adapter validates it, queues
   a job in Redis and answers at once with a job ID.
2. A worker takes the job, runs the `trivy` CLI as a subprocess against the registry, and converts Trivy's JSON
   into a Harbor vulnerability report or SBOM. The report is gzip-compressed and stored in Redis with a TTL.
3. Harbor polls for the report. It gets a redirect while the scan runs, then the finished report.

Trivy keeps its vulnerability database in the adapter's cache volume and refreshes it from an OCI registry
(`ghcr.io` by default, or a mirror you configure). Redis is the only other dependency, and Harbor's own Redis works.

## What it offers

Compared with the adapter bundled in Harbor:

| | Upstream | This fork |
|---|---|---|
| Published image | `goharbor/trivy-adapter-photon` (Photon OS, built in Harbor's release) | `8gears.container-registry.com/8gcr/harbor-scanner-trivy` (Alpine, via `aquasec/trivy`) |
| Trivy binary | Prebuilt, from the base image | Compiled from source at the pinned version |
| Releases | With Harbor | Independent, follow Trivy releases |
| Image signing | — | cosign keyless + SPDX SBOM attestation |
| Release assets | None (image ships with Harbor) | Image, Helm chart, adapter + Trivy binaries, checksums |
| Redis report storage | Plain JSON, single key | gzip, report split into its own key |
| SBOM accessory fast path | — | Opt-in (`SCANNER_TRIVY_USE_SBOM_ACCESSORY`) |

What that means in operation:

- **"Scan All" that stays within memory.** Upstream, a bulk scan over a few thousand artifacts filled the Redis
  instance the adapter shares with Harbor: 4.83 GiB peak, OOM-killed, Harbor down with it ([#28]). With reports
  compressed ([#31]) and stored in their own key ([#43]), a 3,119-artifact "Scan All" peaks at 274 MB and finishes
  30% faster.
- **Reports 7x smaller in Redis** (5.3x to 17.2x depending on the report), which also lets you keep them longer.
- **Vulnerability scans served from an existing SBOM** ([#38], opt-in). When Harbor already generated an SBOM for
  the image with this adapter, the scan reads it instead of pulling layers: 6x to 35x faster per scan, identical
  findings, automatic fallback to a full image scan. In production, a 4,221-artifact "Scan All" went from 3h 24m to
  1h 30m with zero fallbacks ([measurements](https://github.com/container-registry/harbor-scanner-trivy/pull/38#issuecomment-5506161158)).
- **A Trivy you can patch.** Trivy is compiled from source at the pinned version, so a vulnerable dependency can be
  overridden via `go mod` before Aqua cuts a release. The Trivy version and commit the binary was built from show
  up as the scanner version in Harbor's UI.
- **Releases you can verify.** Every image is cosign-signed keyless and carries an SPDX SBOM attestation; see
  [Install](#install) for the verify command.

This fork has its own version line and is not tied to any Harbor release. Which upstream adapter and Trivy version
a given Harbor release bundles is tracked in the [upstream README][goharbor/harbor-scanner-trivy].

## Install

Harbor >= 2.2 bundles the upstream adapter (`goharbor/trivy-adapter-photon`) as its default scanner. There are two
ways to run this fork instead.

**Standalone, as an external scanner.** Each release publishes a chart:

```sh
helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy
```

Then register `http://harbor-scanner-trivy:8080` under **Interrogation Service > Scanners** in Harbor.

**Inside the [Harbor Helm chart][Harbor Helm chart], replacing the bundled image.** The chart exposes the adapter
image as values. This image runs under the chart's `runAsUser: 10000` security context and serves the scanner API
from there:

```sh
helm repo add harbor https://helm.goharbor.io
helm install harbor harbor/harbor --create-namespace --namespace harbor \
  --set trivy.image.repository=8gears.container-registry.com/8gcr/harbor-scanner-trivy \
  --set trivy.image.tag=vX.Y.Z
```

**Verify what you installed:**

```sh
cosign verify \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-trivy/.github/workflows/publish-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z
```

## Releases

Every adapter release `vX.Y.Z` ships:

- the multi-arch image `8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z` (`linux/amd64`,
  `linux/arm64`), cosign-signed keyless with an SPDX SBOM attestation
- `scanner-trivy_linux-{amd64,arm64}.tar.gz`, `trivy_linux-{amd64,arm64}.tar.gz` and `checksums.txt` as GitHub
  release assets, for running the adapter outside a container or reusing the source-built Trivy
- a matching Helm chart release, `chart-vX.Y.Z` at `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy`,
  with the adapter as its `appVersion`. The chart has its own version line, so a chart-only fix never republishes
  the image

A new Trivy release is picked up by Renovate and, once merged, cuts a matching adapter release. `main` publishes
`:latest` on every push. How releases are cut, and what maintainers do, is in [docs/RELEASES.md](docs/RELEASES.md).

## Configuration

Everything is configured through environment variables at startup. No config files.

### General

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_LOG_LEVEL` | `info` | One of `trace`, `debug`, `info`, `warn`, `warning`, `error`. Logs that level and above; unknown values fall back to `info`. |

### API server

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_API_SERVER_ADDR` | `:8080` | Binding address for the API server |
| `SCANNER_API_SERVER_TLS_CERTIFICATE` | N/A | Absolute path to the x509 certificate file |
| `SCANNER_API_SERVER_TLS_KEY` | N/A | Absolute path to the x509 private key file |
| `SCANNER_API_SERVER_CLIENT_CAS` | N/A | Absolute paths to x509 root CAs used to verify client certificates (mTLS) |
| `SCANNER_API_SERVER_READ_TIMEOUT` | `15s` | Max duration for reading the entire request, including the body |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `15s` | Max duration before timing out writes of the response |
| `SCANNER_API_SERVER_IDLE_TIMEOUT` | `60s` | Max time to wait for the next request when keep-alives are enabled |
| `SCANNER_API_SERVER_METRICS_ENABLED` | `true` | Whether to expose Prometheus metrics on `/metrics` |

### Trivy

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_TRIVY_CACHE_DIR` | `/home/scanner/.cache/trivy` | Trivy cache directory |
| `SCANNER_TRIVY_REPORTS_DIR` | `/home/scanner/.cache/reports` | Trivy reports directory |
| `SCANNER_TRIVY_DEBUG_MODE` | `false` | Enable Trivy debug mode |
| `SCANNER_TRIVY_VULN_TYPE` | `os,library` | Comma-separated vulnerability types: `os`, `library` |
| `SCANNER_TRIVY_SECURITY_CHECKS` | `vuln` | Comma-separated security issues to detect: `vuln`, `config`, `secret` |
| `SCANNER_TRIVY_SEVERITY` | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL` | Comma-separated severities to report |
| `SCANNER_TRIVY_IGNORE_UNFIXED` | `false` | Report only vulnerabilities with a fix available |
| `SCANNER_TRIVY_IGNORE_POLICY` | N/A | Path to a Trivy ignore policy OPA Rego file |
| `SCANNER_TRIVY_SKIP_UPDATE` | `false` | Disable [Trivy DB] downloads |
| `SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE` | `false` | Disable [Trivy JAVA DB] downloads |
| `SCANNER_TRIVY_DB_REPOSITORY` | N/A | Comma-separated OCI repositories to fetch the vulnerability DB from, passed as `--db-repository`. When unset, Trivy's own default applies (`mirror.gcr.io/aquasec/trivy-db`, `ghcr.io/aquasecurity/trivy-db`) |
| `SCANNER_TRIVY_JAVA_DB_REPOSITORY` | N/A | Comma-separated OCI repositories to fetch the Java DB from, passed as `--java-db-repository`. When unset, Trivy's own default applies (`mirror.gcr.io/aquasec/trivy-java-db`, `ghcr.io/aquasecurity/trivy-java-db`) |
| `SCANNER_TRIVY_OFFLINE_SCAN` | `false` | Disable external API requests used to identify dependencies |
| `SCANNER_TRIVY_GITHUB_TOKEN` | N/A | Forwarded to Trivy as `GITHUB_TOKEN`. Raises the GitHub API rate limit for VEX repository downloads (`SCANNER_TRIVY_VEX_SOURCE=repo`). Not involved in [Trivy DB] downloads, which come from OCI registries |
| `SCANNER_TRIVY_INSECURE` | `false` | Skip verifying the registry certificate |
| `SCANNER_TRIVY_TIMEOUT` | `5m0s` | How long to wait for a scan to complete |
| `SCANNER_TRIVY_VEX_SOURCE` | N/A | Enable VEX: `oci` or `repo` [EXPERIMENTAL] |
| `SCANNER_TRIVY_SKIP_VEX_REPO_UPDATE` | `false` | Skip updating the VEX repository [EXPERIMENTAL] |
| `SCANNER_TRIVY_USE_SBOM_ACCESSORY` | `false` | Serve vulnerability scans from an existing SBOM accessory found via the OCI referrers API instead of pulling image layers. Vulnerability scans only; requires SBOMs generated by Harbor with this adapter. Falls back to a full image scan when absent or on failure. See [Performance](#performance). |

### Store and job queue

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_STORE_REDIS_NAMESPACE` | `harbor.scanner.trivy:data-store` | Key namespace for the Redis store |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL` | 2x `SCANNER_TRIVY_TIMEOUT` + 3s | TTL for scan jobs and their reports. Derived from the Trivy timeout when unset; must outlive the longest scan or the report expires before Harbor fetches it |
| `SCANNER_JOB_QUEUE_REDIS_NAMESPACE` | `harbor.scanner.trivy:job-queue` | Key namespace for the Redis-backed job queue |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` | `1` | Number of workers processing the scan job queue |

### Redis connection

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_REDIS_URL` | `redis://localhost:6379` | Redis URI. Standalone: `redis://:password@host:port/db`. Sentinel: `redis+sentinel://:password@host1:port1,host2:port2/monitor-name/db` |
| `SCANNER_REDIS_POOL_MAX_ACTIVE` | `5` | Max connections allocated by the pool |
| `SCANNER_REDIS_POOL_MAX_IDLE` | `5` | Max idle connections in the pool |
| `SCANNER_REDIS_POOL_IDLE_TIMEOUT` | `5m` | Close idle connections after this duration. `0` never closes them |
| `SCANNER_REDIS_POOL_CONNECTION_TIMEOUT` | `1s` | Timeout for connecting to Redis |
| `SCANNER_REDIS_POOL_READ_TIMEOUT` | `1s` | Timeout for reading a single command reply |
| `SCANNER_REDIS_POOL_WRITE_TIMEOUT` | `1s` | Timeout for writing a single command |

### Proxy

| Name | Default | Description |
|------|---------|-------------|
| `HTTP_PROXY` | N/A | URL of the HTTP proxy server |
| `HTTPS_PROXY` | N/A | URL of the HTTPS proxy server |
| `NO_PROXY` | N/A | URLs the proxy settings do not apply to |

## Troubleshooting

<details>
<summary><b>database error: --skip-db-update cannot be specified on the first run</b></summary>

You set `SCANNER_TRIVY_SKIP_UPDATE=true` without providing a database. Download the [Trivy DB] and mount it at
`/home/scanner/.cache/trivy/db/trivy.db`.
</details>

## Documentation

- [Architecture](./docs/ARCHITECTURE.md) - deployment topology.
- [Releases](./docs/RELEASES.md) - full release process, artifacts and maintainer checklist.
- [Helm chart](./deploy/chart/README.md) - chart values.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup and the code of conduct. Two rules matter for every PR:
the title must be a [Conventional Commit](https://www.conventionalcommits.org) (it becomes the squash commit
release-please reads), and every commit needs a DCO sign-off (`git commit -s`). Both are enforced by lefthook
hooks and in CI.

CI on every PR: unit, integration and component tests, `golangci-lint`, yamllint, Helm lint, `govulncheck`,
`typos`, dependency review, and [zizmor] on the workflows (all actions pinned to full SHAs). Hot-path Go benchmarks
guard the scan and transform code against regressions ([#12]):
`go test -bench=. -benchmem ./pkg/trivy/... ./pkg/scan/...`.

---
Harbor Scanner Adapter for Trivy was originally an [Aqua Security](https://aquasec.com) open source project, later
maintained under [goharbor](https://github.com/goharbor/harbor-scanner-trivy). This fork is maintained by
[container-registry.com].

[release-img]: https://img.shields.io/github/release/container-registry/harbor-scanner-trivy.svg?logo=github
[release]: https://github.com/container-registry/harbor-scanner-trivy/releases
[license-img]: https://img.shields.io/github/license/container-registry/harbor-scanner-trivy.svg
[license]: https://github.com/container-registry/harbor-scanner-trivy/blob/main/LICENSE

[Harbor]: https://github.com/goharbor/harbor
[Harbor Helm chart]: https://github.com/goharbor/harbor-helm
[Trivy]: https://github.com/aquasecurity/trivy
[Trivy DB]: https://github.com/aquasecurity/trivy-db
[Trivy JAVA DB]: https://github.com/aquasecurity/trivy-java-db
[goharbor/harbor-scanner-trivy]: https://github.com/goharbor/harbor-scanner-trivy
[container-registry.com]: https://container-registry.com
[zizmor]: https://github.com/zizmorcore/zizmor

[#28]: https://github.com/container-registry/harbor-scanner-trivy/issues/28
[#12]: https://github.com/container-registry/harbor-scanner-trivy/pull/12
[#31]: https://github.com/container-registry/harbor-scanner-trivy/pull/31
[#38]: https://github.com/container-registry/harbor-scanner-trivy/pull/38
[#43]: https://github.com/container-registry/harbor-scanner-trivy/pull/43
