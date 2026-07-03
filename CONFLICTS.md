# Upstream sync needs manual resolution

@bupd @vad1mo

Fork tag v0.37.2 already exists but does not point at the expected synced release commit. The workflow will not move existing tags.

## Target

- Repository: container-registry/harbor-scanner-trivy
- Upstream: goharbor/harbor-scanner-trivy
- Target ref: cd2f0ab9c3c91b03aa5d1109ed1aa4cff8f32302
- Workflow run: https://github.com/container-registry/harbor-scanner-trivy/actions/runs/28632392115

## Details

Existing tag commit: ea4e7c5add3698112e761214b5825caf217ec23b
Expected tag commit: cd2f0ab9c3c91b03aa5d1109ed1aa4cff8f32302

## Fork commits considered

```
+ 4fd69a409468695aeb9c9acc07962cc539f6b981 fix: validate layer media types and return structured scan errors
+ e22d0a734827b2f44b38d88dca6e2946b4b26aae chore: add upstream sync workflow (#15)
```

Resolve this manually, remove this file, and merge the resolved upstream sync into main.
