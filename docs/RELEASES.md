# Release Process

Releases are automated with [release-please](https://github.com/googleapis/release-please). Do not create `v*` or `chart-v*` tags, or GitHub Releases, manually.

There are **two independent release lines**, each with its own release-please
instance, config, manifest, changelog and tag namespace:

| Line | Covers | Tag | Config / manifest | Changelog |
|------|--------|-----|-------------------|-----------|
| Adapter | everything except `helm/`, `.github/`, `docs/`, `taskfile/` | `vX.Y.Z` | `release-please-config.json` / `.release-please-manifest.json` | `CHANGELOG.md` |
| Helm chart | `helm/harbor-scanner-trivy/` | `chart-vX.Y.Z` | `release-please-config-chart.json` / `.release-please-manifest-chart.json` | `helm/harbor-scanner-trivy/CHANGELOG.md` |

They are separate so a chart fix does not force an adapter release that
republishes an identical image, and an adapter release does not republish an
unchanged chart. The two are linked in one direction only: the adapter line owns
`appVersion` in `helm/harbor-scanner-trivy/Chart.yaml` (via the
`x-release-please-version` marker), the chart line owns `version`. Both are
driven by the same `Release Please` workflow on every push to `main`.

Release state is defined by:

- Conventional squash commit titles on `main`
- The config and manifest files above (each manifest holds its line's last published version)
- The changelogs above

## How It Works

1. PRs are squash-merged to `main` with conventional commit titles. The PR title becomes the commit release-please parses, so the repository must allow **squash merging only** (disable merge commits and rebase merging).
2. On every push to `main`, the `Release Please` workflow opens or updates a release PR **per line**, for whichever line has releasable commits:
   - `chore: release X.Y.Z` bumps `.release-please-manifest.json`, updates `CHANGELOG.md`, and stamps `appVersion` into `helm/harbor-scanner-trivy/Chart.yaml`.
   - `chore: release harbor-scanner-trivy chart X.Y.Z` bumps `.release-please-manifest-chart.json`, updates the chart's `CHANGELOG.md`, and stamps `version` into `Chart.yaml`.
3. Squash-merging a release PR creates its tag (`vX.Y.Z` or `chart-vX.Y.Z`) and GitHub Release.
4. An **adapter** release then automatically:
   - builds and pushes the multi-arch (`linux/amd64`, `linux/arm64`) image `8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z`
   - signs the image with cosign (keyless) and attaches an SPDX SBOM attestation
   - uploads the adapter and Trivy binaries as release assets
   - appends image references and cosign verification commands to the release notes
5. A **chart** release automatically:
   - appends the per-release `artifacthub.io/images` annotation to `Chart.yaml` (not committed - the tag is only known at release time)
   - packages the chart at the tag's version and pushes it to `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy`
   - signs the chart with cosign (keyless)
   - pushes `artifacthub-repo.yml` as a separate OCI artifact under the `artifacthub.io` tag, which is what gives Artifact Hub the ownership metadata
   - appends install and verification instructions to the chart release notes

   The chart release does **not** wait on an image build: the chart references
   the adapter by `appVersion`, which a prior adapter release must already have
   published.

Every push to `main` additionally publishes `8gears.container-registry.com/8gcr/harbor-scanner-trivy:latest` via the `Main Image` workflow.

## Version Rules

Only `feat:`, `fix:`, and breaking changes trigger a release. All other types
do not cause a release on their own; they are listed in the changelog when the
next release is cut (or hidden entirely).

| Commit type | Bump | Notes section |
|-------------|------|---------------|
| `feat:` | Minor | Features |
| `fix:` | Patch | Bug Fixes |
| `feat!:` or `BREAKING CHANGE:` | Major (Minor while on 0.x, via `bump-minor-pre-major`) | Breaking changes |
| `perf:` | None (changelog only) | Performance Improvements |
| `upstream:` | None (changelog only) | Upstream |
| `revert:` | None (changelog only) | Reverts |
| `refactor:` | None (changelog only) | Code Refactoring |
| `docs:` | None (changelog only) | Documentation |
| `ci:`, `chore:`, `build:`, `test:` | None | Hidden |

Use `upstream:` for changes synced from `goharbor/harbor-scanner-trivy`.

The same rules apply to both lines. Which line a commit lands on is decided by
its paths: the adapter line ignores `.github/`, `docs/`, `helm/` and `taskfile/`;
the chart line only sees `helm/harbor-scanner-trivy/`. A commit touching both
opens both release PRs. Use `ci:` for workflow-only changes.

Scope chart commits explicitly - `feat(chart):`, `fix(chart):` - so the two
changelogs read clearly side by side.

## Release Artifacts

| Artifact | Location |
|----------|----------|
| Container image | `8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z` (and `:latest` from `main`) |
| Helm chart | `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy:X.Y.Z`, cosign-signed |
| Artifact Hub repo metadata | `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy:artifacthub.io` |
| Adapter binaries | `scanner-trivy_linux-{amd64,arm64}.tar.gz` release assets |
| Trivy binaries | `trivy_linux-{amd64,arm64}.tar.gz` release assets (built from source at the `TRIVY_BASE_IMAGE_VERSION` pin) |
| Checksums | `checksums.txt` release asset (SHA256 of all tarballs) |
| Changelog | `CHANGELOG.md` and the GitHub Release |

The Trivy CLI is compiled from source (`task build:trivy`) with the same flags as
Trivy's own release builds, and the container image ships that binary instead of
the prebuilt one from the `aquasec/trivy` base image. This keeps the binary
CVE-patchable via `go mod` overrides and lets downstream consumers (e.g.
harbor-next) take the adapter and Trivy as version-coupled artifacts: binary,
image, or source, from one release.

Install the chart:

```sh
helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy \
  --version X.Y.Z
```

Verify an image signature:

```sh
cosign verify \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-trivy/.github/workflows/publish-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z
```

Verify a chart signature:

```sh
cosign verify \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-trivy/.github/workflows/publish-chart.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy:X.Y.Z
```

Verify the SBOM attestation:

```sh
cosign verify-attestation \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-trivy/.github/workflows/publish-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type spdxjson \
  8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z
```

## Required Configuration

| Name | Type | Required | Purpose |
|------|------|----------|---------|
| `REGISTRY_ADDRESS` | Variable | No | Registry host, defaults to `8gears.container-registry.com` |
| `REGISTRY_PROJECT` | Variable | No | Registry project, defaults to `8gcr` |

Artifact Hub listing (one-off): add the repository at
[artifacthub.io](https://artifacthub.io) as kind *Helm*, URL
`oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy`, then put
the ID it assigns into `repositoryID` in
`helm/harbor-scanner-trivy/artifacthub-repo.yml` to enable the verified-publisher
badge.

There is no registry password anywhere: publish jobs authenticate keyless through
Harbor's Federated Identity Provider. The job mints a GitHub OIDC token
(`id-token: write`, audience `https://<registry>`), logs in with `-u jwt` and the
token as password, and Harbor maps it to the federated robot
`robot_gh-scanner-trivy-push` via a claim rule that only matches this repository's
tokens (`repository == container-registry/harbor-scanner-trivy`). The robot has no
secret; there is nothing to rotate or leak. See
[harbor-workload-identity-federation](https://github.com/container-registry/harbor-workload-identity-federation).

Repository settings:

- Enable only **Allow squash merging**.
- Settings > Actions > General: allow GitHub Actions to create and approve pull requests (release-please opens the release PR with `GITHUB_TOKEN`).

## Maintainer Checklist

Before merging a normal PR:

1. PR title is a valid conventional commit.
2. Merge method is **Squash and merge**.

Before merging an adapter release PR:

1. Version bump matches the commits since the last release.
2. `CHANGELOG.md` and `Chart.yaml` (`appVersion`) both show the new version.
3. Merge method is **Squash and merge**.
4. After merge, the `Release Please` workflow completes and the release notes include the image references.

Before merging a chart release PR:

1. `helm/harbor-scanner-trivy/CHANGELOG.md` and `Chart.yaml` (`version`) show the new chart version.
2. `Chart.yaml` `appVersion` points at an adapter version that is already published.
3. `release-as` is **not** still pinned in `release-please-config-chart.json`. It
   pins the first chart release at `1.0.0`, and must be removed after that
   release ships, or every later chart release repeats `1.0.0`.
4. Merge method is **Squash and merge**.

## Manual Intervention

Manual intervention should be rare:

- Rerun a failed release workflow job.
- Never push replacement tags or edit published releases unless maintainers agree the release is unrecoverable.
