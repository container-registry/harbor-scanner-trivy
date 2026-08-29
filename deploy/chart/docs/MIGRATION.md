# Migrating to chart 1.0.0

Chart 1.0.0 is a ground-up redesign. It is **not** values-compatible with the
pre-1.0 chart: the `scanner.*` tree is gone, credentials moved to an
`existingSecret` family, and probes became data instead of hardcoded template
blocks.

Nothing about the adapter's on-disk or Redis state changed, so the upgrade is a
values translation, not a data migration.

## Before you upgrade

The chart is now versioned independently of the adapter (tags `chart-vX.Y.Z`),
so `--version` selects the chart and `appVersion` selects the adapter image.

Two things are worth checking on a running install:

1. **The scan job TTL.** The old chart's `scanner.store.redisScanJobTTL` had no
   default, and neither does the new `store.redisScanJobTTL`. Left empty, the
   adapter derives it as `2 * trivy.timeout + 3s`. If you had set it, carry the
   value over.
2. **The store namespace.** The old chart shipped
   `scanner.store.redisNamespace: harbor.scanner.trivy:store`, which is *not*
   the adapter's own default (`harbor.scanner.trivy:data-store`). The new chart
   uses the adapter's default. If you never overrode it, your existing keys sit
   under `...:store` and will be orphaned - they expire on their own TTL, and
   in-flight scans at upgrade time are lost. Set
   `store.redisNamespace: harbor.scanner.trivy:store` to keep the old namespace.

## Values mapping

### Renamed

| Pre-1.0 | 1.0.0 |
|---------|-------|
| `scanner.logLevel` | `logLevel` |
| `scanner.api.readTimeout` | `api.readTimeout` |
| `scanner.api.writeTimeout` | `api.writeTimeout` |
| `scanner.api.idleTimeout` | `api.idleTimeout` |
| `scanner.api.tlsEnabled` | `api.tls.enabled` |
| `scanner.api.tlsCertificate` | `api.tls.certificate` (or `api.tls.existingSecret`) |
| `scanner.api.tlsKey` | `api.tls.key` (or `api.tls.existingSecret`) |
| `scanner.trivy.*` | `trivy.*` |
| `scanner.trivy.VEXSource` | `trivy.vexSource` |
| `scanner.trivy.gitHubToken` | `trivy.gitHubToken` (or `trivy.existingSecret`) |
| `scanner.store.*` | `store.*` |
| `scanner.jobQueue.*` | `jobQueue.*` |
| `scanner.redis.poolURL` | `redis.url` (or `redis.existingSecret`) |
| `scanner.redis.poolMaxActive` | `redis.pool.maxActive` |
| `scanner.redis.poolMaxIdle` | `redis.pool.maxIdle` |
| `scanner.redis.poolIdleTimeout` | `redis.pool.idleTimeout` |
| `scanner.redis.poolConnectionTimeout` | `redis.pool.connectionTimeout` |
| `scanner.redis.poolReadTimeout` | `redis.pool.readTimeout` |
| `scanner.redis.poolWriteTimeout` | `redis.pool.writeTimeout` |
| `httpProxy` | `proxy.httpProxy` |
| `httpsProxy` | `proxy.httpsProxy` |
| `noProxy` | `proxy.noProxy` |
| `persistence.accessMode` (string) | `persistence.accessModes` (list) |

### Changed defaults

| Value | Pre-1.0 | 1.0.0 | Why |
|-------|---------|-------|-----|
| `image.tag` | pinned to the adapter version | empty, follows `appVersion` | The chart now has its own version line |
| `resources` | `{}` | 200m/512Mi requests, 1Gi memory limit | An unbounded scanner is a noisy neighbour; a burst-heavy workload needs a floor |
| `terminationGracePeriodSeconds` | 30 (Kubernetes default) | 60 | Lets an in-flight scan finish rather than being killed mid-run |
| `store.redisNamespace` | `harbor.scanner.trivy:store` | `harbor.scanner.trivy:data-store` | Matches the adapter's own default - see the note above |
| `securityContext` | privileged/readOnlyRootFilesystem only | plus `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` | Passes kube-linter and Trivy's config checks unchanged |
| `podSecurityContext` | no `runAsGroup`/`seccompProfile` | adds both | Same |

### Removed

`scanner.trivy.ignorePolicy` still exists, but the ConfigMap it renders was
renamed from `<fullname>-ignorepolicy` to `<fullname>-ignore-policy`. If you
referenced that name outside the chart, update it - or switch to
`trivy.existingIgnorePolicyConfigMap` and own the ConfigMap yourself.

### Fixed

`SCANNER_TRIVY_VEX_SOURCE` and `SCANNER_TRIVY_SKIP_VEX_REPO_UPDATE` were nested
inside the TLS conditional in the pre-1.0 template, so **VEX filtering only
took effect when the API was serving TLS**. They are now independent, which
means a non-TLS install that set `VEXSource` starts honouring it on upgrade.

## New capabilities

None of these are required. All default to off except `serviceAccount.create`,
which creates a dedicated ServiceAccount for you.

| Value | What it does |
|-------|--------------|
| `trivy.existingSecret` / `redis.existingSecret` / `api.tls.existingSecret` | Read credentials from Secrets you own instead of inlining them |
| `image.digest`, `global.imageRegistry` | Digest pinning and one-knob registry mirroring |
| `serviceAccount.*` | A dedicated ServiceAccount, with annotations for IRSA / Workload Identity |
| `probes.*` | Full probe specs, including a startup probe for the cold DB download |
| `podDisruptionBudget.*`, `autoscaling.*` | PDB and HPA |
| `metrics.serviceMonitor.*` | Prometheus Operator scraping |
| `networkPolicy.*` | Ingress (and optionally egress) restriction |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName` | Scheduling |
| `api.tls.clientCAs` | Mutual TLS |
| `extraCA.*` | Trust a private CA for outbound connections (`existingSecret` / `existingConfigMap`) |
| `trivy.cacheBackend`, `trivy.cacheTTL`, `trivy.cacheMaxSize` | Bound the Trivy scan cache, or move it to Redis so several workers can share it. Needs an adapter build that reads `SCANNER_TRIVY_CACHE_*` |
| `extraEnv`, `extraVolumes`, `initContainers`, `sidecars`, `extraManifests` | Extension points |

## Worked example

Pre-1.0:

```yaml
image:
  tag: v0.40.0
scanner:
  logLevel: info
  trivy:
    gitHubToken: ghp_xxxxxxxxxxxx
    severity: HIGH,CRITICAL
    timeout: 10m0s
  redis:
    poolURL: redis://:hunter2@redis:6379/5
    poolMaxActive: 10
persistence:
  enabled: true
  accessMode: ReadWriteOnce
  size: 10Gi
httpProxy: http://proxy:3128
```

1.0.0, with both credentials moved into Secrets you create:

```yaml
logLevel: info
trivy:
  existingSecret: harbor-scanner-trivy-github
  existingSecretKey: token
  severity: HIGH,CRITICAL
  timeout: 10m0s
redis:
  existingSecret: harbor-scanner-trivy-redis
  existingSecretKey: url
  pool:
    maxActive: 10
persistence:
  enabled: true
  accessModes:
    - ReadWriteOnce
  size: 10Gi
proxy:
  httpProxy: http://proxy:3128
# Keep the pre-1.0 key namespace; drop this to adopt the adapter's default.
store:
  redisNamespace: harbor.scanner.trivy:store
```

```sh
kubectl -n harbor create secret generic harbor-scanner-trivy-github \
  --from-literal=token=ghp_xxxxxxxxxxxx
kubectl -n harbor create secret generic harbor-scanner-trivy-redis \
  --from-literal=url='redis://:hunter2@redis:6379/5'
```

## If the upgrade fails to render

That is the intended behaviour: the closed `values.schema.json` rejects every
key that no longer exists, naming it. Work through the list against the table
above - `helm template` locally until it renders, then upgrade.

## Changing persistence after install

`volumeClaimTemplates` is immutable. The 1.0 claim template renders exactly what
the pre-1.0 chart rendered, so `helm upgrade` from 0.x is not rejected over it,
and nothing about the cache volume has to be touched during the migration.

Changing `persistence.size`, `persistence.storageClass` or
`persistence.accessModes` on an existing release is a different matter. The API
server rejects the update:

```
UPGRADE FAILED: cannot patch "harbor-scanner-trivy" with kind StatefulSet:
StatefulSet.apps "harbor-scanner-trivy" is invalid: spec: Forbidden: updates to
statefulset spec for fields other than 'replicas', 'ordinals',
'template', 'updateStrategy', 'persistentVolumeClaimRetentionPolicy' and
'minReadySeconds' are forbidden
```

Replace the StatefulSet, keeping the data:

```sh
# 1. Keep the values you are running.
helm get values harbor-scanner-trivy -n harbor > current-values.yaml

# 2. Drop the StatefulSet object only. --cascade=orphan leaves the pods running
#    and the PVCs untouched; scanning keeps working throughout.
kubectl delete statefulset harbor-scanner-trivy -n harbor --cascade=orphan

# 3. Upgrade with the new persistence values. The recreated StatefulSet adopts
#    the orphaned pods by selector and reuses the PVCs by name (data-<name>-0).
helm upgrade harbor-scanner-trivy <chart> -n harbor \
  -f current-values.yaml --set persistence.size=20Gi
```

A larger `persistence.size` in the claim template applies to PVCs the
StatefulSet creates from then on, not to the ones that already exist. To grow
those, the StorageClass needs `allowVolumeExpansion: true` and each PVC has to
be patched:

```sh
kubectl patch pvc data-harbor-scanner-trivy-0 -n harbor \
  -p '{"spec":{"resources":{"requests":{"storage":"20Gi"}}}}'
```

If you would rather start clean, the volume holds only Trivy's caches. Deleting
the PVC costs one vulnerability-DB download and a cold scan cache, nothing more.
