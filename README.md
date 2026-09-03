[![GitHub Release][release-img]][release]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Trivy

Translates the [Harbor] scanner API into [Trivy] commands, so Harbor can report vulnerabilities and SBOMs for the
images it stores using Trivy. It is the default vulnerability scanner in Harbor >= 2.2.

This repository is a fork of [goharbor/harbor-scanner-trivy], maintained by [container-registry.com].

<img src="docs/images/vulnerabilities.png" alt="Vulnerability report in the Harbor UI" width="720">

## Contents

- [Why this fork](#why-this-fork)
- [Performance](#performance)
- [Install](#install)
- [Release flow](#release-flow)
- [Version matrix](#version-matrix)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Contributing](#contributing)

## Why this fork

Upstream ships the adapter that Harbor bundles, on Harbor's release cadence. We run Harbor as a service and needed
three things that cadence and scope do not cover:

1. **Scan throughput and memory.** A bulk "Scan All" over a few thousand artifacts filled the Redis instance
   the adapter shares with Harbor: 4.83 GiB peak, OOM-killed, Harbor down with it ([#28]). Fixing that meant
   changing how scan reports are stored, not how they are produced.
2. **The Trivy binary itself.** Upstream consumes the prebuilt `aquasec/trivy` binary. We compile Trivy from source
   at the pinned version, which makes its dependencies patchable via `go mod` overrides when a CVE lands before
   Aqua cuts a release.
3. **Our own release train.** Signed, attested, multi-arch artifacts published on demand rather than when the next
   Harbor version ships.

Nothing here is a protocol fork: the Harbor scanner API, the report format and the findings are unchanged. Upstream
commits are cherry-picked back into this fork twice a day by
[an automated workflow](.github/workflows/upstream-cherry-pick.yml), and carry the `upstream:` commit type.

| | Upstream | This fork |
|---|---|---|
| Published image | `goharbor/trivy-adapter-photon` (Photon OS, built in Harbor's release) | `8gears.container-registry.com/8gcr/harbor-scanner-trivy` (Alpine, via `aquasec/trivy`) |
| Trivy binary | Prebuilt, from the base image | Compiled from source at the pinned version |
| Releases | With Harbor | Independent, automated (release-please) |
| Image signing | — | cosign keyless + SPDX SBOM attestation |
| Release assets | None (image ships with Harbor) | Image, Helm chart, adapter + Trivy binaries, checksums |
| Redis report storage | Plain JSON, single key | gzip, report split into its own key |
| SBOM accessory fast path | — | Opt-in (`SCANNER_TRIVY_USE_SBOM_ACCESSORY`) |

## Performance

- **Scan reports are gzip-compressed in Redis** ([#31]) - stored reports shrink about 7x (5.3x-17.2x depending on the report).
- **The report lives in its own Redis key** ([#43]) - a 3,119-artifact "Scan All" finishes 30% faster and peaks at 274 MB, roughly 18x below the pre-compression baseline in [#28].
- **Vulnerability scans can be served from an existing SBOM accessory** ([#38], opt-in) - 6x to 35x faster per scan, with identical findings and a fallback to a full image scan. In production, a 4,221-artifact "Scan All" dropped from 3h 24m to 1h 30m with 100% fast-path uptake and zero fallbacks ([measurements](https://github.com/container-registry/harbor-scanner-trivy/pull/38#issuecomment-5506161158)).

Hot-path Go benchmarks guard against regressions ([#12]): `go test -bench=. -benchmem ./pkg/trivy/... ./pkg/scan/...`.

## Install

**As Harbor's built-in scanner.** In Harbor >= 2.0 Trivy is the default scanner and the
[official Harbor Helm chart][Harbor Helm chart] (>= 1.4) installs the adapter for you:

```sh
helm repo add harbor https://helm.goharbor.io
helm install harbor harbor/harbor --create-namespace --namespace harbor
```

The adapter registers itself under **Interrogation Service** as the default scanner.

**Standalone, as an external scanner.** Each release publishes a chart:

```sh
helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy
```

Then register `http://harbor-scanner-trivy:8080` under **Interrogation Service > Scanners** in Harbor.

**Verify what you installed:**

```sh
cosign verify \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-trivy/.github/workflows/publish-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z
```

## Release flow

Releases are fully automated. Full detail in [docs/RELEASES.md](docs/RELEASES.md).

```
conventional PR title -> squash merge to main -> release-please opens "chore: release adapter X.Y.Z"
                                                            |
                                          squash merge that PR -> vX.Y.Z tag + GitHub Release
                                                            |
                       multi-arch image + cosign signature + SBOM attestation + Helm chart + binaries
```

- **Version comes from commits.** `feat:` bumps the minor, `fix:` the patch. `perf:`, `refactor:`, `docs:` and
  `upstream:` show up in the changelog without cutting a release; `chore:`/`ci:`/`build:`/`test:` are hidden.
  The repo allows squash merges only, because the PR title is the commit release-please parses.
- **One release produces every artifact:** the multi-arch image (`linux/amd64`, `linux/arm64`), the Helm chart
  at `oci://.../charts/harbor-scanner-trivy`, `scanner-trivy_linux-{amd64,arm64}.tar.gz` and
  `trivy_linux-{amd64,arm64}.tar.gz` tarballs, and `checksums.txt`. Downstream consumers can take the adapter and
  Trivy as version-coupled artifacts, as source, binary or image.
- **Signed and attested.** Every image is cosign-signed keyless and carries an SPDX SBOM attestation.
- **No registry credentials exist.** Publishing authenticates through Harbor's federated identity provider: the job
  mints a GitHub OIDC token and Harbor maps it to a secretless robot scoped to this repository. Nothing to rotate,
  nothing to leak. See [harbor-workload-identity-federation].
- **`main` publishes `:latest`** on every push, and every PR gets a preview image build.

CI on every PR: unit, integration and component tests, `golangci-lint`, yamllint, Helm lint, `govulncheck`,
`typos`, dependency review, and [zizmor] on the workflows (all actions pinned to full SHAs).

## Version matrix

Which adapter and Trivy version each [Harbor release](https://github.com/goharbor/harbor/releases) bundles. These
are the *upstream* adapter versions; this fork releases independently and is not tied to a Harbor release.

| Harbor          | Trivy Adapter | Trivy           |
|-----------------|---------------|-----------------|
| harbor v2.16.0  | v0.38.0       | [trivy v0.72.0](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0) |
| harbor v2.15.1  | v0.36.0       | [trivy v0.70.0](https://github.com/aquasecurity/trivy/releases/tag/v0.70.0) |
| harbor v2.15.0  | v0.35.1       | [trivy v0.69.3](https://github.com/aquasecurity/trivy/releases/tag/v0.69.3) |
| harbor v2.14.2  | v0.34.2       | [trivy v0.68.2](https://github.com/aquasecurity/trivy/releases/tag/v0.68.2) |
| harbor v2.14.1  | v0.34.0       | [trivy v0.66.0](https://github.com/aquasecurity/trivy/releases/tag/v0.66.0) |
| harbor v2.14.0  | v0.34.0       | [trivy v0.66.0](https://github.com/aquasecurity/trivy/releases/tag/v0.66.0) |
| harbor v2.13.4  | v0.34.2       | [trivy v0.68.2](https://github.com/aquasecurity/trivy/releases/tag/v0.68.2) |
| harbor v2.13.2  | v0.33.2       | [trivy v0.64.1](https://github.com/aquasecurity/trivy/releases/tag/v0.64.1) |
| harbor v2.13.1  | v0.33.1       | [trivy v0.62.1](https://github.com/aquasecurity/trivy/releases/tag/v0.62.1) |
| harbor v2.13.0  | v0.33.0-rc.2  | [trivy v0.61.0](https://github.com/aquasecurity/trivy/releases/tag/v0.61.0) |
| harbor v2.12.3  | v0.32.4       | [trivy v0.61.1](https://github.com/aquasecurity/trivy/releases/tag/v0.61.1) |
| harbor v2.12.2  | v0.32.3       | [trivy v0.58.2](https://github.com/aquasecurity/trivy/releases/tag/v0.58.2) |
| harbor v2.12.1  | v0.32.2       | [trivy v0.57.1](https://github.com/aquasecurity/trivy/releases/tag/v0.57.1) |
| harbor v2.12.0  | v0.32.0       | [trivy v0.56.1](https://github.com/aquasecurity/trivy/releases/tag/v0.56.1) |

Not exhaustive. For older versions see [aquasecurity/harbor-scanner-trivy].

## Configuration

Everything is configured through environment variables at startup. No config files.

### General

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_LOG_LEVEL` | `info` | One of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal`, `panic`. Logs that level and above. |

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
| `SCANNER_TRIVY_IGNORE_POLICY` | `` | Path to a Trivy ignore policy OPA Rego file |
| `SCANNER_TRIVY_SKIP_UPDATE` | `false` | Disable [Trivy DB] downloads |
| `SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE` | `false` | Disable [Trivy JAVA DB] downloads |
| `SCANNER_TRIVY_DB_REPOSITORY` | `mirror.gcr.io/aquasec/trivy-db,ghcr.io/aquasecurity/trivy-db` | OCI repositories to fetch the vulnerability DB from |
| `SCANNER_TRIVY_JAVA_DB_REPOSITORY` | `ghcr.io/aquasecurity/trivy-java-db` | OCI repositories to fetch the Java vulnerability DB from |
| `SCANNER_TRIVY_OFFLINE_SCAN` | `false` | Disable external API requests used to identify dependencies |
| `SCANNER_TRIVY_GITHUB_TOKEN` | N/A | GitHub token for [Trivy DB] downloads (see [rate limiting][gh-rate-limit]) |
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
| `SCANNER_REDIS_URL` | `redis://harbor-harbor-redis:6379` | Redis URI. Standalone: `redis://:password@host:port/db`. Sentinel: `redis+sentinel://:password@host1:port1,host2:port2/monitor-name/db` |
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

<details>
<summary><b>failed to list releases: ... dial tcp: lookup api.github.com ... i/o timeout</b></summary>

A Docker DNS or firewall issue. Trivy needs internet access to refresh its vulnerability database. Add a DNS server
to the `docker-compose.yml` created by the Harbor installer:

```yaml
version: 2
services:
  trivy-adapter:
    # NOTE Adjust IPs to your environment.
    dns:
      - 8.8.8.8
      - 192.168.1.1
```

Alternatively configure the Docker daemon to use the host's DNS server; see [DNS services][docker-dns].
</details>

<details>
<summary><b>failed to list releases: ... 403 API rate limit exceeded</b></summary>

Trivy DB downloads from GitHub are [rate limited][gh-rate-limit]. Mount and cache the DB at
`/home/scanner/.cache/trivy/db/trivy.db`. If that is not enough, set `SCANNER_TRIVY_GITHUB_TOKEN`; authenticated
requests get a higher limit.
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

---
Harbor Scanner Adapter for Trivy was originally an [Aqua Security](https://aquasec.com) open source project, later
maintained under [goharbor](https://github.com/goharbor/harbor-scanner-trivy). This fork is maintained by
[container-registry.com].

[release-img]: https://img.shields.io/github/release/container-registry/harbor-scanner-trivy.svg?logo=github
[release]: https://github.com/container-registry/harbor-scanner-trivy/releases
[report-card-img]: https://goreportcard.com/badge/github.com/container-registry/harbor-scanner-trivy
[report-card]: https://goreportcard.com/report/github.com/container-registry/harbor-scanner-trivy
[license-img]: https://img.shields.io/github/license/container-registry/harbor-scanner-trivy.svg
[license]: https://github.com/container-registry/harbor-scanner-trivy/blob/main/LICENSE

[Harbor]: https://github.com/goharbor/harbor
[Harbor Helm chart]: https://github.com/goharbor/harbor-helm
[Trivy]: https://github.com/aquasecurity/trivy
[Trivy DB]: https://github.com/aquasecurity/trivy-db
[Trivy JAVA DB]: https://github.com/aquasecurity/trivy-java-db
[goharbor/harbor-scanner-trivy]: https://github.com/goharbor/harbor-scanner-trivy
[aquasecurity/harbor-scanner-trivy]: https://github.com/aquasecurity/harbor-scanner-trivy
[container-registry.com]: https://container-registry.com
[harbor-workload-identity-federation]: https://github.com/container-registry/harbor-workload-identity-federation
[zizmor]: https://github.com/zizmorcore/zizmor
[gh-rate-limit]: https://github.com/aquasecurity/trivy#github-rate-limiting
[docker-dns]: https://docs.docker.com/config/containers/container-networking/#dns-services

[#28]: https://github.com/container-registry/harbor-scanner-trivy/issues/28
[#12]: https://github.com/container-registry/harbor-scanner-trivy/pull/12
[#31]: https://github.com/container-registry/harbor-scanner-trivy/pull/31
[#38]: https://github.com/container-registry/harbor-scanner-trivy/pull/38
[#43]: https://github.com/container-registry/harbor-scanner-trivy/pull/43
