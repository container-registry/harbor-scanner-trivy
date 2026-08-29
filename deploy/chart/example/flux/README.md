# GitOps delivery with FluxCD

Everything Flux applies has to be deterministic: the chart must render
byte-identically on every reconcile, or the drift detector reports a change
forever. This chart generates nothing at render time - there is no
`randAlphaNum` anywhere - so determinism only depends on you pinning what you
own:

- **the image**, by digest (`image.digest`), not by a floating tag
- **the chart**, by exact `version` in the HelmRelease
- **every secret**, in a Secret you create (`redis.existingSecret`,
  `trivy.existingSecret`, `api.tls.existingSecret`)

CI enforces the first half of that: it renders `ci/gitops-values.yaml` twice and
fails on any diff.

The same values work unchanged under Argo CD.

## Apply

```sh
kubectl apply -k .
```

Two things in this directory are **placeholders** and must be replaced before
you apply it: the image digest in `helmrelease.yaml` (all zeros, resolves to
nothing) and the credentials in `identity-secrets.yaml`.

`identity-secrets.yaml` in this directory is a **placeholder**. Do not commit
real credentials: seal them (Sealed Secrets), encrypt them (SOPS), or have the
External Secrets Operator produce the same Secret names.

## Files

| File | Purpose |
|------|---------|
| `namespace.yaml` | Target namespace |
| `source.yaml` | `OCIRepository` pointing at the chart in the registry |
| `identity-secrets.yaml` | Placeholder Secrets the release expects to exist. Kept in this kustomization for a self-contained example; if another controller (SOPS, Sealed Secrets, ESO) owns these names, drop this file from `resources` so the two do not fight over the same objects |
| `helmrelease.yaml` | The release itself, with drift detection enabled |
| `kustomization.yaml` | Ties them together in apply order |
