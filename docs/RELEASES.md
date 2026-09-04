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

## Pull Request Previews

Two workflows publish review artifacts into the dev project (`8gcr-dev`, see
`PR_REGISTRY_PROJECT`) and leave one sticky comment each on the PR with the
reference, the digest and the cosign verification command. Each runs only when
the PR diff touches an input that reaches its artifact:

| Workflow | Triggers on | Publishes | Signing identity |
|----------|-------------|-----------|------------------|
| `PR Preview Image` (`pr-image.yml`) | `cmd/`, `pkg/`, `go.mod`, `go.sum`, `Dockerfile`, `versions.env`, `Taskfile.yml`, the image workflows, `.github/actions/setup/` | `8gears.container-registry.com/8gcr-dev/harbor-scanner-trivy:pr-N` | `publish-image.yml` |
| `PR Preview Chart` (`pr-chart.yml`) | `deploy/chart/`, `pr-chart.yml`, `chart-annotate-images.sh` | `oci://8gears.container-registry.com/8gcr-dev/charts/harbor-scanner-trivy:X.Y.Z-pr.N` | `pr-chart.yml` |

Both run on every push while the cumulative PR diff matches, and both overwrite
the same tag, so `pr-N` and `X.Y.Z-pr.N` always point at the latest successful
build; pin the digest from the comment when that matters. `X.Y.Z` is the chart
version committed in `Chart.yaml`, and the preview keeps the committed
`appVersion`, so it installs a released adapter by default. `--set
image.repository=8gcr-dev/harbor-scanner-trivy --set image.tag=pr-N` pairs it with
the PR's preview image when one exists; the preview image lives in the dev
project, so the tag alone is not enough.

No preview is published for forked PRs and dependabot PRs (no OIDC token), nor
for release-please PRs: a release PR changes no code, and the chart release PR
only restamps version, changelog and README.

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

## Behaviour That Looks Like a Bug

Each of these cost a debugging session in this repository. None of them is a bug.

- **Without `always-update`, an open release PR is refreshed only when its body would change.**
  `createOrUpdatePullRequest` in release-please's `src/manifest.ts` branches on the option: with it,
  `updateExistingPullRequest` runs unconditionally; without it, `maybeUpdateExistingPullRequest`
  returns early when `existing.body === pullRequest.body.toString()` and logs `PR #N remained the
  same`. Moving or renaming the config and manifest files does not change that body, so the open PR
  keeps pointing at the old paths. Editing `pull-request-header` is the opposite case, because the
  header is the first line of the body being compared. Both configs here set `always-update: true`,
  so neither line is exposed now; its absence on the chart line is what stranded chart PR #74 when
  #75 moved the manifests into `.release-please/` (fixed in #76). Keep it on both lines.

- **`release-as` in a config is permanent, not one-shot.** It pins every later release to the same
  version, so the release after the one it was meant for proposes that version again and merging it
  collides with the existing tag. The chart line hit exactly this: with `chart-v1.0.0` already tagged,
  the next chart release PR proposed `1.0.0` again, and the fix was to delete the pin (#70). The
  schema now marks `release-as` deprecated in favour of a `Release-As: X.Y.Z` commit footer, which
  applies once.

- **A new release line starts at 1.0.0 whatever its manifest says.** With no tag to walk back to,
  `initialReleaseVersion()` in release-please's `src/strategies/base.ts` returns the config's
  `initial-version` when set and `1.0.0` otherwise. A manifest seeded with `0.0.0` is never consulted
  on that path. Neither line here is exposed today, because `0.40.1` and `1.0.1` both have matching
  tags, but a third line added later needs `initial-version` in its config. Do not reach for
  `release-as`, which is the trap above.

- **`exclude-paths` drops a commit only when every file it touches is excluded.** The schema is
  explicit: "If all files from commit belong to one of the paths it will be skipped". One file outside
  `.github`, `docs`, `deploy`, `taskfile` and `.release-please` therefore pulls a whole workflow-only
  commit into the adapter changelog and bumps the adapter version. The inverse surprises more: a
  `feat:` whose every file sits under an excluded path releases nothing at all, and that reads as
  release-please being broken rather than as configuration doing its job.

- **A hidden commit type cannot carry a release into the other line.** `chore: release adapter X.Y.Z`
  is a `chore:` commit as far as the chart line is concerned. While `chore` was hidden there,
  release-please found an empty changelog and opened nothing, so a chart with the new `appVersion`
  only shipped when the next `fix(chart)` happened to land (#78). That is the whole reason `chore` is
  visible in `config-chart.json` and hidden in `config-adapter.json`. Do not tidy it away.

## The Release PR's Checks Wait for Approval

Both release-please jobs in `release-please.yml` pass `secrets.GITHUB_TOKEN`, so the release PR is
opened by `github-actions[bot]`. GitHub does create the workflow runs, and then holds every one of
them in the `action_required` state until somebody with write access clicks **Approve and run**. On
the two open release PRs, `CI`, `Hygiene`, `Chart CI`, `PR Title` and `PR Preview Chart` all sit at
`action_required`; on the merged adapter release #44 those same workflows ran to success once a
maintainer approved them. A release PR whose checks list looks empty is waiting for a person, not
broken.

That approval is a manual step on every release PR, and it is what a required status check turns into
a merge block, because the context reports nothing until the run is approved. The active `Min` ruleset
on `main` blocks branch deletion and force-pushes and requires no status check, so nothing is blocked
today.

To require checks without the approval step, make release-please open its PR as a GitHub App, whose
pushes are not gated this way:

```yaml
- uses: actions/create-github-app-token@<sha>  # vX.Y.Z
  id: app-token
  with:
    app-id: ${{ vars.RELEASE_APP_ID }}
    private-key: ${{ secrets.RELEASE_APP_PRIVATE_KEY }}

- uses: googleapis/release-please-action@<sha>  # vX.Y.Z
  with:
    token: ${{ steps.app-token.outputs.token }}
```

Then require only a context that reports on every pull request. `Hygiene` is the one workflow here
with no path filter; `CI` has `paths-ignore` and `Chart CI` has `paths`. A path-filtered workflow does
not report at all on a PR that misses its filter, so requiring one leaves that PR waiting forever.

Do not work around a blocked release PR by pushing its tag by hand. The tag and that line's manifest
then disagree permanently: release-please finds no previous release, walks the whole history, and
replays old commits into the next changelog.

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
| `PR_REGISTRY_PROJECT` | Variable | No | Project the PR preview image and chart go to, defaults to `8gcr-dev` |

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

1. Version bump matches the commits since the last release. If it does not, the cause is usually a commit type or a path, see [Behaviour That Looks Like a Bug](#behaviour-that-looks-like-a-bug); fix the config and push to `main`, and the PR rewrites itself.
2. `CHANGELOG.md` and `Chart.yaml` (`appVersion`) both show the new version.
3. `release-as` is absent from `.release-please/config-adapter.json`.
4. Merge method is **Squash and merge**.
5. After merge, the `Release Please` workflow completes and the release notes include the image references.

Before merging a chart release PR:

1. `deploy/chart/CHANGELOG.md`, `Chart.yaml` (`version`) and `README.md` (cosign example) show the new chart version. A release PR that does not touch `README.md` means the restamp markers broke.
2. `Chart.yaml` `appVersion` points at an adapter version that is already published. After an adapter release the chart changelog shows `release adapter X.Y.Z` under Miscellaneous; that entry is expected.
3. `release-as` is absent from `.release-please/config-chart.json` (see [Behaviour That Looks Like a Bug](#behaviour-that-looks-like-a-bug)).
4. Merge method is **Squash and merge**.

## Manual Intervention

Manual intervention should be rare:

- Rerun a failed release workflow job.
- Never push replacement tags or edit published releases unless maintainers agree the release is unrecoverable.
