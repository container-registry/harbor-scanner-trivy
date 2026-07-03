# Release Process

Releases are automated with [release-please](https://github.com/googleapis/release-please). Do not create `v*` tags or GitHub Releases manually.

Release state is defined by:

- Conventional squash commit titles on `main`
- `release-please-config.json`
- `.release-please-manifest.json` (last published version)
- `CHANGELOG.md`

## How It Works

1. PRs are squash-merged to `main` with conventional commit titles. The PR title becomes the commit release-please parses, so the repository must allow **squash merging only** (disable merge commits and rebase merging).
2. On every push to `main`, the `Release Please` workflow opens or updates a `chore: release X.Y.Z` PR. The PR bumps `.release-please-manifest.json`, updates `CHANGELOG.md`, and stamps the version into `helm/harbor-scanner-trivy/Chart.yaml` (`version`, `appVersion`) and `helm/harbor-scanner-trivy/values.yaml` (`image.tag`) via the `x-release-please-version` annotations.
3. Squash-merging the release PR creates the `vX.Y.Z` tag and GitHub Release.
4. The release then automatically:
   - builds and pushes the multi-arch (`linux/amd64`, `linux/arm64`) image `8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z`
   - signs the image with cosign (keyless) and attaches an SPDX SBOM attestation
   - packages and pushes the Helm chart to `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy`
   - appends image references, Helm install instructions, and cosign verification commands to the release notes

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

Release-please ignores commits that only touch `.github/` or `docs/`. Use `ci:` for workflow-only changes.

## Release Artifacts

| Artifact | Location |
|----------|----------|
| Container image | `8gears.container-registry.com/8gcr/harbor-scanner-trivy:vX.Y.Z` (and `:latest` from `main`) |
| Helm chart | `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy` |
| Changelog | `CHANGELOG.md` and the GitHub Release |

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
| `RUNNER` | Variable | No | Custom runner label |
| `REGISTRY_ADDRESS` | Variable | No | Registry host, defaults to `8gears.container-registry.com` |
| `REGISTRY_PROJECT` | Variable | No | Registry project, defaults to `8gcr` |
| `REGISTRY_USERNAME` | Variable | Yes | Registry push username |
| `REGISTRY_PASSWORD` | Secret | Yes | Registry push password/token |

Repository settings:

- Enable only **Allow squash merging**.
- Settings > Actions > General: allow GitHub Actions to create and approve pull requests (release-please opens the release PR with `GITHUB_TOKEN`).

## Maintainer Checklist

Before merging a normal PR:

1. PR title is a valid conventional commit.
2. Merge method is **Squash and merge**.

Before merging a release PR:

1. Version bump matches the commits since the last release.
2. `CHANGELOG.md`, `Chart.yaml` (`version`, `appVersion`), and `values.yaml` (`image.tag`) all show the new version.
3. Merge method is **Squash and merge**.
4. After merge, the `Release Please` workflow completes and the release notes include image and chart references.

## Manual Intervention

Manual intervention should be rare:

- Rerun a failed release workflow job.
- Never push replacement tags or edit published releases unless maintainers agree the release is unrecoverable.
