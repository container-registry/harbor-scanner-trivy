# Contributing

## Table of Contents

* [Set up Local Development Environment](#set-up-local-development-environment)
* [Build](#build)
* [Run Tests](#run-tests)
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

Tool and base-image version pins live in [`versions.env`](versions.env).
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

Both are enforced locally by [lefthook](lefthook.yml) hooks (installed via `task setup`)
and in CI.

[fowler-testing-strategies]: https://www.martinfowler.com/articles/microservice-testing/
