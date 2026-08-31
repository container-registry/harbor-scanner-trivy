# Contributing to the chart

The repo-wide rules are in [`/CONTRIBUTING.md`](../../CONTRIBUTING.md). This
covers what is specific to the chart.

## Design principles

1. **Nothing is generated at render time.** No `randAlphaNum`, no timestamps.
   Two renders of the same values must be byte-identical, or every GitOps engine
   reports perpetual drift. `task helm:gitops-determinism` enforces it.
2. **Every credential has an `existingSecret` form.** Inline values are a
   convenience for test installs; the BYO-Secret path is the supported one, and
   it is what keeps secrets out of Git and out of the pod spec.
3. **Fail at render time, not in the cluster.** A mistake that would surface as
   a CrashLoopBackOff, a Pending pod, or a silently wrong scan belongs in
   `values.schema.json` (shape) or `templates/validate-values.yaml`
   (cross-field). Nothing that a schema can express belongs in a guard - the
   schema runs first, and the guard would be unreachable.
4. **The values surface is closed.** The schema root is
   `additionalProperties: false`, so a typo fails instead of being ignored.
   That makes the escape hatches load-bearing: `config`/`secret` for adapter
   settings, the `*Overrides` merges for Kubernetes fields, `extraManifests` for
   whole objects. If something is unreachable, add a hatch rather than a knob.

## Adding a value

Five places, in order. `task helm:lint:schema` fails on drift between the first
two, and `task helm:docs:check` on the last.

1. `values.yaml` - with a `# --` helm-docs comment saying *why*, not restating
   the key name. Note non-obvious consequences.
2. `values.schema.json` - the tightest type that is still correct. Enums and
   patterns here are better error messages than a template failure.
3. `templates/` - and if it interacts with another value, a guard in
   `validate-values.yaml`.
4. `tests/` - at least one `it:` for the value's effect, and one for its guard.
5. `task helm:docs` to regenerate `README.md`. Never hand-edit it; edit
   `README.md.gotmpl`.

Consider whether it belongs in an `example/` scenario. CI renders all of them,
so an example that rots fails the build.

## Backward compatibility

The chart has its own release line, so a values break is a chart major. Renaming
or removing a value means a `feat!:` commit and an entry in
[`docs/MIGRATION.md`](docs/MIGRATION.md) - the closed schema turns a rename into
a hard render failure for every existing user, which is the intended behaviour
but only helps if the migration doc tells them what to do.

## Running the gate

```sh
task helm:ci               # everything CI runs
task helm:unittest         # just the unit tests
task helm:unittest:update  # regenerate snapshots - read the diff
task helm:tools:test       # golden tests for tools/
task helm:docs             # regenerate README.md
```

`task helm:kubescape` is an on-demand audit, not part of the gate: it needs a
local binary and fetches framework definitions at run time.

## Conventions

- Commits touching only this directory should be scoped `feat(chart):`,
  `fix(chart):` and so on, so the two changelogs read clearly side by side.
- Comments explain a non-obvious constraint or trade-off. A comment restating
  what the next line does is noise; a comment recording *why* the env order
  matters, or why a directory is listed twice, is the point.
