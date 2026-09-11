# Dedicated Valkey analysis cache

This example deploys the official `valkey` chart 0.9.3 from
`oci://ghcr.io/valkey-io/valkey-helm`, the same version used by Harbor-next.
The cache instance belongs to the scanner release.
Enable it with `valkey.enabled: true`; the adapter's default `trivy.cacheBackend:
fs` then resolves to the subchart's primary Service automatically.

```sh
helm dependency build deploy/chart --skip-refresh
helm upgrade --install scanner deploy/chart -n harbor \
  -f deploy/chart/example/dedicated-cache/values.yaml
```

The deployment has three adapter pods with one worker each. Keep `redis.*`
pointing to the job/report backend: this analysis cache evicts keys and cannot
safely store pending jobs or reports.

The defaults are `maxmemory 512mb`, `allkeys-lru`, a 1 GiB container limit,
and disabled snapshots/AOF. Size the memory budget and headroom for the working
set. After a cache restart, Trivy analyzes the affected images again. Upstream resources, persistence, ACL, TLS and network-policy
settings pass through under `valkey`. Avoid naming this service after Harbor's
existing operational Valkey instance.

For authentication, provision a Secret `trivy-cache-auth` with `default` (ACL
password) and `url` (full credential URL; URL-encode the password). For release
`scanner` the URL is `redis://default:<encoded-password>@scanner-valkey:6379/0`.
Merge this configuration into the example values:

```yaml
valkey:
  enabled: true
  auth:
    enabled: true
    usersExistingSecret: trivy-cache-auth
    aclUsers:
      default:
        permissions: "~* &* +@all"
extraEnv:
  - name: SCANNER_TRIVY_CACHE_BACKEND
    valueFrom:
      secretKeyRef:
        name: trivy-cache-auth
        key: url
```

Helm validation rejects authentication settings without an adapter URL
override. Supply the passwords in the Secret; rendering does not generate them. For TLS, configure the upstream
`valkey.tls` server Secret and the adapter CA/client certificate paths described
in [the scaling guide](../../../../docs/SCALING.md). The automatic URL selects
`rediss://` when server TLS is enabled; explicit Secret URLs must do so too.

For an external analysis cache, leave `valkey.enabled: false` (the default)
and configure `trivy.cacheBackend` or its Secret override.
