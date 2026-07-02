# Upstream sync needs manual resolution

@bupd @vad1mo

Fork tag v0.37.2 already exists but does not point at the expected synced release commit. The workflow will not move existing tags.

## Target

- Repository: container-registry/harbor-scanner-trivy
- Upstream: goharbor/harbor-scanner-trivy
- Target ref: 1fee0139715b0ff6118ea2cfd02126299dd7b941
- Workflow run: https://github.com/container-registry/harbor-scanner-trivy/actions/runs/28593468478

## Details

Existing tag commit: ea4e7c5add3698112e761214b5825caf217ec23b
Expected tag commit: 1fee0139715b0ff6118ea2cfd02126299dd7b941

## Fork commits considered

```
+ 4fd69a409468695aeb9c9acc07962cc539f6b981 fix: validate layer media types and return structured scan errors
+ e22d0a734827b2f44b38d88dca6e2946b4b26aae chore: add upstream sync workflow (#15)
```

Resolve this manually, remove this file, and merge the resolved upstream sync into main.
