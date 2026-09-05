# Contributing

## Table of Contents

* [Set up Local Development Environment](#set-up-local-development-environment)
* [Build](#build)
* [Run Tests](#run-tests)
* [Check for Vulnerabilities](#check-for-vulnerabilities)
* [Test Against a Local Harbor](#test-against-a-local-harbor)
* [Commit Conventions](#commit-conventions)

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
* Every commit must carry a DCO sign-off (`git commit -s`).

On a pull request the [PR Title](.github/workflows/pr-title.yml) workflow checks the title
that becomes the squash commit, and the [dco2](https://github.com/apps/dco-2) app checks the
sign-off on every commit. The [lefthook](lefthook.yml) hooks (installed via `task setup`) and
`task commit-lint` / `task dco-check` mirror the same two rules locally, so a branch that
passes them passes the pull request.

[fowler-testing-strategies]: https://www.martinfowler.com/articles/microservice-testing/
