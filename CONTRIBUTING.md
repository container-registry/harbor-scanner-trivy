# Contributing

## Table of Contents

* [Set up Local Development Environment](#set-up-local-development-environment)
* [Build](#build)
* [Run Tests](#run-tests)
* [Check for Vulnerabilities](#check-for-vulnerabilities)
* [Test Against a Local Harbor](#test-against-a-local-harbor)
* [Commit Conventions](#commit-conventions)
* [Release Notes](#release-notes)

## Set up Local Development Environment

1. Install Go.

   The required Go version is declared in [`go.mod`](go.mod).
2. Install [Task](https://taskfile.dev) and Docker.
3. Get the source code.
   ```
   git clone https://github.com/container-registry/harbor-scanner-trivy.git
   cd harbor-scanner-trivy
   ```
4. Install pinned development tools and git hooks.
   ```
   task setup
   ```

Tool and base-image version pins live in [`versions.env`](versions.env). The dependency
versions forced onto the Trivy CLI we build from source live in
[`trivy-cve-overrides.txt`](trivy-cve-overrides.txt), which documents how to re-check them.
Run `task --list` to see all available tasks and `task info` for the build configuration.

## Build

Build the binary for your native platform into `bin/<os>-<arch>/scanner-trivy`:

```
task build
```

Build a local container image `harbor-scanner-trivy:<version>`:

```
task image:local
```

## Run Tests

Unit testing alone doesn't provide guarantees about the behaviour of the adapter. To verify that each Go module
correctly interacts with its collaborators, more coarse grained testing is required as described in
[Testing Strategies in a Microservice Architecture][fowler-testing-strategies].

```
task test              # unit tests with race detection and coverage
task test:integration  # integration tests (requires Docker and the trivy CLI in PATH)
task test:component    # component tests (requires Docker; builds the image first)
task lint              # golangci-lint
```

## Check for Vulnerabilities

Scan the module dependency graph with the pinned [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck):

```
task vuln-check
```

CI runs the same scan through `task vuln-report`, which stores the raw JSON in
`vulnerability-check/` and renders it into markdown. Run it locally to see exactly what CI
reports:

```
task vuln-report                       # writes vulnerability-check/report.md and comment.md
cat vulnerability-check/report.md      # every finding
cat vulnerability-check/comment.md     # only findings with a published fix
```

`report.md` goes to the workflow job summary and `comment.md` becomes a sticky pull request
comment that is updated on every re-run and removed once nothing fixable is left. Findings do
not fail the job; only a govulncheck run that could not produce a usable report does, which
`task vuln-report:check` verifies.

The renderer lives in [`tools/govulncheck-report`](tools/govulncheck-report) and can also be
pointed at a report you produced yourself:

```
govulncheck -format json ./... > govulncheck.json
go run ./tools/govulncheck-report -json govulncheck.json -mode fixable
```

## Test Against a Local Harbor

The scanner is consumed by Harbor as a scanner adapter. To test a locally built image against
a running Harbor instance, point the `trivy-adapter` service of your Harbor deployment at the
image built by `task image:local` and restart the service. With a compose-based Harbor
installation, edit `docker-compose.yml`:

```yaml
services:
  trivy-adapter:
    container_name: trivy-adapter
    image: harbor-scanner-trivy:dev
    restart: always
```

## Commit Conventions

Releases are automated with [release-please](https://github.com/googleapis/release-please);
see [docs/RELEASES.md](docs/RELEASES.md). Two rules follow from that:

* Commit messages (and PR titles, which become the squash commit) follow
  [Conventional Commits](https://www.conventionalcommits.org): `feat:` triggers a minor
  release, `fix:` a patch release; `chore:`/`ci:`/`build:`/`test:` do not trigger releases.
* A Trivy bump uses the type Renovate gives it in [`renovate.json`](renovate.json): a patch
  bump of `TRIVY_BASE_IMAGE_VERSION` is `fix(deps):`, a minor or major one `feat(deps):`,
  and a Go toolchain bump that clears an advisory is `fix(deps):`. Each changes the shipped
  image, and a `chore(deps):` title leaves it unreleased on `main`.
* Every commit must carry a DCO sign-off (`git commit -s`).

On a pull request the [PR Title](.github/workflows/pr-title.yml) workflow checks the title
that becomes the squash commit, and the [dco2](https://github.com/apps/dco-2) app checks the
sign-off on every commit. The [lefthook](lefthook.yml) hooks (installed via `task setup`) and
`task commit-lint` / `task dco-check` catch most of what those gates would reject, before
you push. The pull request title is a separate value that only the workflow checks, so give
it the same conventional format.

The dco2 app is the authoritative sign-off gate, so where it and the local check disagree,
the app decides. The local check is deliberately stricter about placement and letter case
(the sign-off must be in the trailer block, spelled `Signed-off-by:`), and it does not
verify that the sign-off identity matches the commit author or committer, which the app
does.

[fowler-testing-strategies]: https://www.martinfowler.com/articles/microservice-testing/

## Release Notes

`feat:` and `fix:` pull requests end their description with a `## Release Notes` section. After a release
is published, `release-notes.yml` puts that text under the pull request's entry in the GitHub release, so
readers see each note next to the change it explains. It does not affect `CHANGELOG.md`.

```markdown
## Release Notes

Adds federated OIDC support. Configure it with the new `federated_oidc` key;
see the [OIDC documentation](https://docs.example.com/oidc).
```

**Write notes when, without them, someone running the scanner would act differently after upgrading or be
surprised by what changed.** For `feat:` that is almost always the case. A `fix:` qualifies when at least
one of these holds:

- **Action needed**: users change config, migrate, clean up or re-check something
- **Behaviour change**: something works differently or stops working, or a default or permission changes
- **New decision**: the fix adds a setting users may want to set
- **Security fix** with an advisory (GHSA or CVE)
- **Visible failure gone**: an outage, data loss or regression users noticed and may have worked around

Otherwise write `N/A`: internal fixes without a visible symptom, refactors, plumbing, dependency bumps
without a CVE, and bugs that never shipped in a release.

**Rules** (the `PR Release Notes` check enforces them):

- `feat:` and `fix:` pull requests need the section; its content is the notes or `N/A`. Breaking changes
  (`feat!:`, `fix!:`) need notes
- At most 550 characters as rendered; link targets, images and Markdown markers do not count. Put details in
  the docs and link to them
- Last section of the description, with no headings inside. Any heading ends the section, so `### Tests`
  placed below it is not published
- No alert boxes such as `> [!NOTE]`; they do not render inside the release's change list. Use plain text or
  **bold**
