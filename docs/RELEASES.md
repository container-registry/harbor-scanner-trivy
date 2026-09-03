# Release Process

Releases are automated with [release-please](https://github.com/googleapis/release-please). Do not create `v*` or `chart-v*` tags, or GitHub Releases, manually.

There are **two independent release lines**, each with its own release-please
instance, config, manifest, changelog and tag namespace:

| Line | Covers | Tag | Config / manifest | Changelog |
|------|--------|-----|-------------------|-----------|
| Adapter | everything except `deploy/`, `.github/`, `docs/`, `taskfile/`, `.release-please/` | `vX.Y.Z` | `.release-please/config-adapter.json` / `.release-please/manifest-adapter.json` | `CHANGELOG.md` |
| Helm chart | `deploy/chart/` | `chart-vX.Y.Z` | `.release-please/config-chart.json` / `.release-please/manifest-chart.json` | `deploy/chart/CHANGELOG.md` |

They are separate so a chart fix does not force an adapter release that
republishes an identical image, and an adapter release does not republish the
chart by itself. The two are linked in one direction only: the adapter line owns
`appVersion` in `deploy/chart/Chart.yaml` (via the
`x-release-please-version` marker), the chart line owns `version`. Because the
adapter release commit touches `Chart.yaml`, and `chore:` is visible in the chart
changelog, every adapter release also opens or refreshes the chart release PR
with a `release adapter X.Y.Z` entry; merging that PR publishes a chart whose
`appVersion` is the new adapter. Both lines are driven by the same
`Release Please` workflow on every push to `main`.

Release state is defined by:

- Conventional squash commit titles on `main`
- The config and manifest files above (each manifest holds its line's last published version)
- The changelogs above

## How It Works

1. PRs are squash-merged to `main` with conventional commit titles. The PR title becomes the commit release-please parses, so the repository must allow **squash merging only** (disable merge commits and rebase merging).
2. On every push to `main`, the `Release Please` workflow opens or updates a release PR **per line**, for whichever line has releasable commits:
   - `chore: release adapter X.Y.Z` bumps `.release-please/manifest-adapter.json`, updates `CHANGELOG.md`, and stamps `appVersion` into `deploy/chart/Chart.yaml`.
   - `chore: release chart X.Y.Z` bumps `.release-please/manifest-chart.json`, updates the chart's `CHANGELOG.md`, and stamps `version` into `Chart.yaml` and the cosign example in the chart `README.md`.
3. Squash-merging a release PR creates its tag (`vX.Y.Z` or `chart-vX.Y.Z`) and GitHub Release.
4. An **adapter** release then automatically:
   - builds and pushes the multi-arch (`linux/amd64`, `linux/arm64`) image `8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z`
   - signs the image with cosign (keyless) and attaches an SPDX SBOM attestation
   - uploads the adapter and Trivy binaries as release assets
   - appends image references and cosign verification commands to the release notes
   - opens or refreshes the chart release PR (`chore: release chart X.Y.Z`), so a chart with the new `appVersion` ships as soon as that PR is merged
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

A release PR opens as soon as a line has at least one commit of a type that is
shown in its changelog. Hidden types never open a release on their own. The
bump is decided by the highest-ranking commit: breaking > `feat:` > everything
else.

| Commit type | Bump | Notes section |
|-------------|------|---------------|
| `feat!:` or `BREAKING CHANGE:` | Major (Minor while on 0.x, via `bump-minor-pre-major`) | Breaking changes |
| `feat:` | Minor | Features |
| `fix:` | Patch | Bug Fixes |
| `perf:`, `upstream:`, `revert:`, `refactor:`, `docs:` | Patch | Performance Improvements, Upstream, Reverts, Code Refactoring, Documentation |
| `chore:` | Adapter: hidden, no release. Chart: Patch | Chart only: Miscellaneous. This is what carries an adapter release (`chore: release adapter X.Y.Z` stamps `appVersion`) into a chart release |
| `ci:`, `build:`, `test:` | Hidden, no release | - |

Use `upstream:` for changes synced from `goharbor/harbor-scanner-trivy`.

The same rules apply to both lines, except that `chore:` is shown only in the
chart changelog. Which line a commit lands on is decided by
its paths: the adapter line ignores `.github/`, `docs/`, `deploy/`, `taskfile/` and
`.release-please/`; the chart line only sees `deploy/chart/`. A commit touching both
opens both release PRs. Use `ci:` for workflow-only changes.

Scope chart commits `feat(chart):` / `fix(chart):` and keep them inside the
paths the adapter ignores. One file outside, even `README.md`, puts the commit
in the adapter changelog and bumps the adapter version. The `Chart Scope Paths`
check fails such a PR; split it rather than retype it. When `exclude-paths` in
`.release-please/config-adapter.json` changes, update that check's patterns too.

## Tracking Upstream Trivy

The adapter tracks upstream Trivy's release cadence via the org's self-hosted
Renovate (weekly cron). Pins in `versions.env` are invisible to dependabot, so
each carries a `# renovate:` annotation read by the regex manager in
`renovate.json`. The Trivy pin uses the `docker` datasource against
`aquasec/trivy`, so a bump PR only appears once the base-image tag the
Dockerfile is `FROM` actually exists.

`renovate.json` maps the Trivy update type to the conventional commit type -
`fix:` for a Trivy patch release, `feat:` for anything bigger - so
squash-merging the Renovate PR makes release-please cut a matching adapter
release. `versions.env` sits on the adapter release line, so a pin bump
releases the adapter artifacts (see Release Artifacts below).

Review is deliberately manual: `versions.env` changes trigger the PR preview
image, which compiles Trivy from source at the new pin and asserts every entry
in `trivy-cve-overrides.txt` against the pristine tag, so a stale override
fails the build instead of shipping.

Renovate is limited to `versions.env` (`enabledManagers: custom.regex`);
dependabot keeps gomod and github-actions. The typos pin stays unmanaged
because its hand-computed checksum pin must be updated together with it.

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

Verify the published architectures:

```sh
task image:verify IMAGE_TAG=vX.Y.Z
```

The publish workflow runs the same check on the pushed digest, so a build that
loses an architecture fails the release instead of shipping. The task asserts
the reference is an OCI image index whose platforms are exactly
`IMAGE_PLATFORMS` (`linux/amd64,linux/arm64`); `IMAGE_REF=...` verifies an
arbitrary reference, `PLATFORMS=...` a different expectation.

## Required Configuration

| Name | Type | Required | Purpose |
|------|------|----------|---------|
| `REGISTRY_ADDRESS` | Variable | No | Registry host, defaults to `8gears.container-registry.com` |
| `REGISTRY_PROJECT` | Variable | No | Registry project, defaults to `8gcr` |

Artifact Hub listing (one-off): add the repository at
[artifacthub.io](https://artifacthub.io) as kind *Helm*, URL
`oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy`, then put
the ID it assigns into `repositoryID` in
`deploy/chart/artifacthub-repo.yml` to enable the verified-publisher
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

1. `deploy/chart/CHANGELOG.md`, `Chart.yaml` (`version`) and `README.md` (cosign example) show the new chart version. A release PR that does not touch `README.md` means the restamp markers broke.
2. `Chart.yaml` `appVersion` points at an adapter version that is already published. After an adapter release the chart changelog shows `release adapter X.Y.Z` under Miscellaneous; that entry is expected.
3. Keep `release-as` **absent** from `.release-please/config-chart.json`.
   The initial chart release used `release-as: 1.0.0`; do not re-add it,
   or every later chart release repeats `1.0.0`.
4. Merge method is **Squash and merge**.

## Manual Intervention

Manual intervention should be rare:

- Rerun a failed release workflow job.
- Never push replacement tags or edit published releases unless maintainers agree the release is unrecoverable.
