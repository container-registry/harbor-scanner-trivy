# harbor-scanner-trivy

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.40.0](https://img.shields.io/badge/AppVersion-v0.40.0-informational?style=flat-square)

A production-ready Helm chart for the Harbor Scanner Adapter for Trivy - the vulnerability and SBOM scanner behind Harbor's Interrogation Services.

The adapter implements Harbor's scanner adapter API: Harbor posts a scan
request, the adapter queues it in Redis, a worker shells out to the `trivy` CLI,
and the result is transformed into a Harbor vulnerability report or SBOM. It is
the scanner behind Harbor's Interrogation Services.

## Prerequisites

- Kubernetes >= 1.28
- A Redis reachable from the cluster. Harbor's own Redis is the usual choice;
  give the adapter its own database number (Harbor uses `0`-`4`).
- A Harbor >= 2.2 to register the scanner with.
- A StorageClass, unless you set `persistence.enabled: false` and accept
  re-downloading the Trivy DB on every restart.
- Egress to `ghcr.io` for the Trivy databases, or a mirror - see
  [`example/air-gapped/`](example/air-gapped/).

## Install

```sh
helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy \
  --namespace harbor --create-namespace
```

Then register the scanner in Harbor under **Administration -> Interrogation
Services -> Scanners -> NEW SCANNER**, using the endpoint the chart prints on
install:

```
http://harbor-scanner-trivy.harbor.svc:8080
```

The defaults assume Harbor's own Redis at `redis://harbor-harbor-redis:6379`.
Point `redis.url` at yours, or read the whole URL out of a Secret with
`redis.existingSecret` (see [`example/external-redis/`](example/external-redis/)).

## What this chart gives you

- **Secrets stay yours.** Every credential has an `existingSecret` form -
  the GitHub token, the Redis URL (password included), the TLS keypair - so
  nothing sensitive has to live in a values file or in Git.
- **Deterministic renders.** Nothing is generated at render time, so Argo CD and
  Flux see no drift. CI renders the GitOps values twice and fails on any diff.
- **Fail-fast validation.** A closed `values.schema.json` rejects unknown or
  malformed keys, and render-time guards catch the cross-field mistakes a schema
  cannot express - TLS enabled with no certificate, a PDB with no budget, one
  RWO claim shared across replicas. They fail `helm template`, not the cluster.
- **Probes as data.** The full Kubernetes probe specs are values, with a startup
  probe that lets a cold Trivy DB download take its time without a liveness
  restart loop. The chart injects `scheme: HTTPS` when you turn TLS on.
- **The whole production surface.** ServiceAccount, PodDisruptionBudget, HPA,
  ServiceMonitor, NetworkPolicy, scheduling constraints, sidecars, init
  containers, and `extraManifests` - each off by default and independently
  switchable.
- **No dead ends.** Every adapter setting is reachable through `config` /
  `secret` without a chart change, and every Kubernetes field the chart does not
  template is reachable through the merge hatches below.

## Configuring the adapter

The adapter is configured entirely by environment variables, so `config` reaches
all of it - including settings added after this chart version:

```yaml
config:
  scanner:
    trivy:
      timeout: 10m0s
      severity: [HIGH, CRITICAL]
    log:
      level: debug
```

Nested keys join with `_` and are uppercased, lists join with `,`, so that
renders `SCANNER_TRIVY_TIMEOUT`, `SCANNER_TRIVY_SEVERITY` and
`SCANNER_LOG_LEVEL` into a ConfigMap consumed with `envFrom`. No prefix is
imposed, so `HTTP_PROXY` and friends are reachable the same way.

`secret` takes the identical notation but renders into a Secret, so the values
never enter the pod spec. Credential-shaped keys in `config` are refused at
render time.

Precedence, lowest to highest:

```
chart defaults  <  config / secret  <  extraEnv
```

Kubernetes evaluates `envFrom` before `env`, so a chart-set variable would
otherwise beat your `config`. The chart drops its own entry for any name you
claim, which is what makes the middle of that chain work.

## Escape hatches

The chart cannot template every field of a StatefulSet. Four deep-merge hooks
cover what it does not expose, and yours wins on conflict:

| Value | Merges into | For example |
|-------|-------------|-------------|
| `statefulSetSpecOverrides` | `.spec` | `minReadySeconds`, `persistentVolumeClaimRetentionPolicy`, `ordinals` |
| `podSpecOverrides` | `.spec.template.spec` | `runtimeClassName`, `hostNetwork`, `enableServiceLinks`, `nodeName` |
| `containerOverrides` | the adapter container | `workingDir`, `terminationMessagePolicy`, `resizePolicy` |
| `persistence.claimSpecOverrides` | the claim template `.spec` | `selector`, `volumeMode`, `dataSource` |

The merge only runs when one is set, so the default render stays in template
order; opting in re-marshals the object (sorted keys, still deterministic).
`extraManifests` covers anything that is a separate object rather than a field.

## Sizing

The Trivy vulnerability DB is downloaded on first start and refreshed every 12
hours. Two settings follow from that:

- **Keep `persistence.enabled`.** Without a volume the DB lives in an
  `emptyDir` and every pod restart re-downloads roughly a gigabyte - slow, and a
  quick way to hit GitHub's anonymous rate limit of 60 requests/hour. Set
  `trivy.gitHubToken` (or `trivy.existingSecret`) to raise that to 5000/hour.
- **Raise memory before raising `jobQueue.workerConcurrency`.** Each concurrent
  scan runs its own Trivy process with the DB loaded, so worker count multiplies
  the memory footprint. `replicaCount` scales throughput the same way, at one
  cache volume per replica.

## TLS

`api.tls.enabled` switches the listener to HTTPS; Harbor must then be registered
with an `https://` endpoint and must trust the issuing CA. Prefer
`api.tls.existingSecret` - it takes a cert-manager `Certificate` Secret
directly. Setting `api.tls.clientCAs` additionally makes the adapter *require* a
client certificate, so Harbor has to present one. See
[`example/tls-cert-manager/`](example/tls-cert-manager/).

## Verifying the chart signature

Chart releases are cosign-signed keylessly by the release workflow, with no
long-lived key to manage:

```sh
cosign verify \
  --certificate-identity-regexp '^https://github\.com/container-registry/harbor-scanner-trivy/\.github/workflows/publish-chart\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy:1.0.0
```

Flux can enforce the same check on every reconcile - see
[`example/flux/`](example/flux/).

## Troubleshooting

**The scanner shows as unhealthy in Harbor.** Harbor calls `/api/v1/metadata`.
Check the adapter answers from inside the cluster, then check Harbor can reach
that exact URL - a TLS-enabled adapter registered with an `http://` endpoint
fails here, and so does an `https://` endpoint whose CA Harbor does not trust.

```sh
kubectl -n harbor exec sts/harbor-scanner-trivy -- \
  wget -qO- http://localhost:8080/probe/ready
```

**Scans stay queued forever.** The worker takes jobs off a Redis queue, so this
is almost always Redis: wrong URL, wrong database, or a password that never
arrived. The adapter logs the failure at startup.

```sh
kubectl -n harbor logs sts/harbor-scanner-trivy | grep -i redis
```

**The pod restarts during its first minutes.** The startup probe allows 60s
(30 failures x 2s) for the initial Trivy DB download. On a slow link, raise
`probes.startup.failureThreshold` rather than the liveness settings.

**`x509: certificate signed by unknown authority`.** The registry, Redis or DB
source is behind a private CA. Use `extraCA` - see
[`example/private-ca/`](example/private-ca/). Do not reach for `trivy.insecure`,
which disables verification everywhere.

**GitHub rate limit on the DB download.** Anonymous downloads get 60
requests/hour. Set `trivy.existingSecret` with a token for 5000/hour, and keep
`persistence.enabled` so the DB is not re-fetched on every restart.

**Permission denied on `/home/scanner/.cache`.** The cache volume is not owned
by the pod's `fsGroup`. On OpenShift see [`example/openshift/`](example/openshift/);
elsewhere check that your StorageClass honours `fsGroup`.

**A values key stopped working after an upgrade.** The schema root is closed, so
an unknown key fails the render by name. Check
[`docs/MIGRATION.md`](docs/MIGRATION.md).

## Uninstalling

```sh
helm uninstall harbor-scanner-trivy --namespace harbor
```

The cache PVCs are created by a StatefulSet volume claim template, so Helm does
not delete them. That is deliberate - it makes an uninstall/reinstall cheap.
Remove them explicitly when you mean it:

```sh
kubectl -n harbor delete pvc -l app.kubernetes.io/name=harbor-scanner-trivy
```

Remove the scanner registration in Harbor as well, or it keeps pointing at a
Service that no longer exists.

## Upgrading from the pre-1.0 chart

Chart 1.0.0 restructured the values. The old `scanner.*` tree is gone, secrets
moved to the `existingSecret` family, and probes became data. See
[`docs/MIGRATION.md`](docs/MIGRATION.md) for a value-by-value mapping.

## Examples

See [`example/`](example/) - Harbor integration, external Redis, cert-manager
TLS, FluxCD, and air-gapped installs. CI renders all of them on every change.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| Harbor Scanner Trivy Authors | <vadim@8gears.com> | <https://github.com/container-registry/harbor-scanner-trivy> |

## Source Code

* <https://github.com/container-registry/harbor-scanner-trivy>

## Requirements

Kubernetes: `>=1.28.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules for pod assignment. |
| api.idleTimeout | string | `"60s"` | Idle timeout for keep-alive connections. |
| api.readTimeout | string | `"15s"` | Maximum duration for reading an entire request, including the body. |
| api.tls.certificate | string | `""` | PEM certificate, inlined into a chart-managed Secret. Ignored when `existingSecret` is set. |
| api.tls.clientCAs.existingConfigMap | string | `""` | Existing ConfigMap holding client CA bundle(s). |
| api.tls.clientCAs.existingSecret | string | `""` | Existing Secret holding client CA bundle(s). Setting this or `existingConfigMap` turns on mutual TLS: the adapter then requires and verifies a client certificate, so Harbor must present one. |
| api.tls.clientCAs.keys | list | `["ca.crt"]` | Keys within the Secret/ConfigMap to trust. Each becomes a file under `/etc/scanner-trivy/client-cas/` and is passed to `SCANNER_API_SERVER_CLIENT_CAS`. |
| api.tls.enabled | bool | `false` | Serve the adapter API over HTTPS. Harbor must then register the scanner with an `https://` URL. |
| api.tls.existingSecret | string | `""` | Existing `kubernetes.io/tls` Secret holding `tls.crt` and `tls.key`. Preferred over inlining PEM in values; works directly with a cert-manager Certificate. Required unless `certificate`/`key` are set. |
| api.tls.key | string | `""` | PEM private key, inlined into a chart-managed Secret. Ignored when `existingSecret` is set. |
| api.writeTimeout | string | `"15s"` | Maximum duration before timing out a response write. This bounds a single HTTP response, not a scan. |
| autoscaling.behavior | object | `{}` | Scaling behavior. |
| autoscaling.enabled | bool | `false` | Create a HorizontalPodAutoscaler. Scaling out provisions a cache PVC per replica, and each new replica downloads the Trivy DB once. |
| autoscaling.maxReplicas | int | `5` | Maximum replicas. |
| autoscaling.metrics | list | `[]` | Extra metrics appended to the generated ones. |
| autoscaling.minReplicas | int | `1` | Minimum replicas. |
| autoscaling.targetCPUUtilizationPercentage | int | `80` | Target average CPU utilization, in percent. `null` drops the metric. |
| autoscaling.targetMemoryUtilizationPercentage | string | `nil` | Target average memory utilization, in percent. `null` drops the metric. |
| commonAnnotations | object | `{}` | Annotations added to every rendered object. |
| commonLabels | object | `{}` | Labels added to every rendered object. |
| config | object | `{}` | Adapter configuration as a nested map, flattened into env vars in a chart-managed ConfigMap and consumed with `envFrom`. Nested keys join with `_` and are uppercased; lists join with `,`:      config:       scanner:         trivy:           timeout: 10m0s     ->   SCANNER_TRIVY_TIMEOUT=10m0s  The adapter is configured entirely by environment, so this reaches every setting it has - including ones added after this chart version, with no chart change. The chart drops its own entry for any name claimed here, because `envFrom` would otherwise lose to it.  A ConfigMap is not secret. Credential-shaped keys are refused at render time; put them in `secret` below. |
| containerOverrides | object | `{}` | Deep-merged into the adapter container, for fields the chart does not template (`workingDir`, `terminationMessagePolicy`, `resizePolicy`). Sidecars are untouched. Yours wins on conflict. |
| dnsConfig | object | `{}` | Pod DNS config. |
| dnsPolicy | string | `""` | Pod DNS policy. |
| extraCA | object | `{"existingConfigMap":"","existingSecret":"","keys":[]}` | Private CA certificates to trust, on top of the system bundle. The adapter and the Trivy CLI it runs are both Go programs, so this covers every outbound TLS call they make: pulling image layers from a registry with an internal CA, a TLS Redis, a proxied Trivy DB source.  The bundle is mounted at `/etc/scanner-trivy/extra-ca` and `SSL_CERT_DIR=/etc/ssl/certs:/etc/scanner-trivy/extra-ca` is set. The system path is listed explicitly on purpose: Go replaces its default directory list when `SSL_CERT_DIR` is set, so omitting it would break every public TLS call. |
| extraCA.existingConfigMap | string | `""` | Existing ConfigMap holding one or more PEM certificates. Mutually exclusive with `existingSecret`. |
| extraCA.existingSecret | string | `""` | Existing Secret holding one or more PEM certificates. Takes a cert-manager CA Secret directly. |
| extraCA.keys | list | `[]` | Keys to mount from it. Empty mounts every key, which is what you want for a bundle; name keys only to mount a subset. |
| extraEnv | list | `[]` | Extra environment variables, in full `EnvVar` form (so `valueFrom` works). Appended last, so a name set here wins over both `config`/`secret` and the chart's own entry. Full precedence, lowest to highest: chart defaults < config / secret < extraEnv. |
| extraEnvFrom | list | `[]` | Extra `envFrom` sources (ConfigMap/Secret references). |
| extraManifests | list | `[]` | Extra raw manifests rendered with the release. Strings are passed through `tpl`, so they may reference `.Values` and `.Release`. |
| extraVolumeMounts | list | `[]` | Extra volume mounts for the adapter container. |
| extraVolumes | list | `[]` | Extra volumes for the adapter pod. |
| fullnameOverride | string | `""` | Override the fully qualified resource name (`<release>-<chart>`). |
| global | object | `{"imagePullSecrets":[],"imageRegistry":""}` | Values shared across the chart (and any future subchart). |
| global.imagePullSecrets | list | `[]` | Image pull secrets applied to every pod in the chart. |
| global.imageRegistry | string | `""` | Registry override applied to every image in the chart. Wins over `image.registry`; the repository path is preserved. Set this to point an air-gapped install at a mirror in one place. |
| hostAliases | list | `[]` | Additional host aliases injected into `/etc/hosts`. |
| image.digest | string | `""` | Image digest (`sha256:...`). Wins over `tag` when set; pin this for immutable, GitOps-friendly deployments. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.pullSecrets | list | `[]` | Image pull secrets for this image, merged with `global.imagePullSecrets`. |
| image.registry | string | `"8gears.container-registry.com"` | Image registry. |
| image.repository | string | `"8gcr/harbor-scanner-trivy"` | Image repository. |
| image.tag | string | `.Chart.AppVersion` | Image tag. |
| imageCredentials | object | `{"create":false,"email":"","password":"","registry":"","username":""}` | Build a `dockerconfigjson` pull Secret from inline credentials, for installs with no pre-existing one to reference. Prefer `image.pullSecrets` with a Secret you own: the password set here is stored in the release. |
| imageCredentials.create | bool | `false` | Create the Secret and add it to the pod's `imagePullSecrets`. |
| imageCredentials.email | string | `""` | Registry account email, which some registries still require. |
| imageCredentials.password | string | `""` | Registry password or token. |
| imageCredentials.registry | string | `global.imageRegistry`, else `image.registry` | Registry the credentials are for. |
| imageCredentials.username | string | `""` | Registry username. |
| initContainers | list | `[]` | Init containers, passed through `tpl`. |
| jobQueue.redisNamespace | string | `"harbor.scanner.trivy:job-queue"` | Key namespace for the scan job queue. |
| jobQueue.workerConcurrency | int | `1` | Workers per replica. Each concurrent scan runs its own Trivy process and holds the vulnerability DB in memory, so raise `resources` alongside this. Above 1 also requires `trivy.cacheBackend` to be Redis or `memory`: those processes cannot share the single-writer `fs` scan cache. |
| lifecycle | object | `{}` | Container lifecycle hooks. |
| logLevel | string | `"info"` | Adapter log level: `trace`, `debug`, `info`, `warn`, `error`. Anything unrecognized falls back to `info`. `debug` also turns on Trivy debug mode unless `trivy.debugMode` is set explicitly. |
| metrics.enabled | bool | `true` | Serve Prometheus metrics on `/metrics` of the API port (`SCANNER_API_SERVER_METRICS_ENABLED`). |
| metrics.serviceMonitor.annotations | object | `{}` | Extra annotations. |
| metrics.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor. Requires the `monitoring.coreos.com/v1` CRD. |
| metrics.serviceMonitor.honorLabels | bool | `false` | Honor labels exposed by the target. |
| metrics.serviceMonitor.interval | string | `""` | Scrape interval. |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels, e.g. the `release` label your Prometheus selects on. |
| metrics.serviceMonitor.metricRelabelings | list | `[]` | Relabeling rules applied to scraped samples. |
| metrics.serviceMonitor.namespace | string | `""` | Namespace for the ServiceMonitor. Defaults to the release namespace. |
| metrics.serviceMonitor.relabelings | list | `[]` | Relabeling rules applied before scraping. |
| metrics.serviceMonitor.scrapeTimeout | string | `""` | Scrape timeout. |
| metrics.serviceMonitor.tlsConfig | object | `{}` | TLS config used when scraping a TLS-enabled adapter. |
| nameOverride | string | `""` | Override the chart name used in resource names and labels. |
| networkPolicy.egress | list | `[]` | Egress rules, used when `networkPolicy.egressEnabled` is set. |
| networkPolicy.egressEnabled | bool | `false` | Restrict egress as well. Leave off unless you enumerate Redis, the registry, and the Trivy DB source in `networkPolicy.egress`. |
| networkPolicy.enabled | bool | `false` | Create a NetworkPolicy for the adapter pods. |
| networkPolicy.ingress | list | `[]` | Peers allowed to reach the API port. Empty allows any source; set this to the Harbor core/jobservice selectors to lock the adapter down. |
| nodeSelector | object | `{}` | Node labels for pod assignment. |
| persistence.accessModes | list | `["ReadWriteOnce"]` | Access modes for the claim template. |
| persistence.annotations | object | `{}` | Annotations for the claim template. |
| persistence.claimSpecOverrides | object | `{}` | Deep-merged into the claim template `.spec`, for fields the chart does not template (`selector`, `volumeMode`, `dataSource`, `dataSourceRef`). Yours wins on conflict. |
| persistence.enabled | bool | `true` | Persist the Trivy vulnerability DB cache on a PVC. With this off the cache lives in an `emptyDir` and every pod restart re-downloads the DB. |
| persistence.existingClaim | string | `""` | Use an existing PVC instead of the StatefulSet volume claim template. Only safe with `replicaCount: 1`. |
| persistence.size | string | `"5Gi"` | Size of the cache volume. The Trivy DB, the Java DB, and unpacked scan workspaces need headroom well beyond the DB size itself. |
| persistence.storageClass | string | `""` | StorageClass for the claim template. `-` selects "no dynamic provisioning"; unset selects the cluster default. |
| podAnnotations | object | `{}` | Annotations added to the adapter pods. |
| podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget. Only useful with `replicaCount` > 1. |
| podDisruptionBudget.maxUnavailable | int | `1` | Maximum unavailable pods. Mutually exclusive with `minAvailable`. |
| podDisruptionBudget.minAvailable | string | `""` | Minimum available pods. Mutually exclusive with `maxUnavailable`. |
| podDisruptionBudget.unhealthyPodEvictionPolicy | string | `"AlwaysAllow"` | `unhealthyPodEvictionPolicy` (Kubernetes >= 1.27). `AlwaysAllow` so a wedged adapter pod cannot block a node drain: an unready scan worker is not serving anyone, and holding the budget open for it only stalls the cluster. |
| podLabels | object | `{}` | Labels added to the adapter pods. |
| podManagementPolicy | string | `"OrderedReady"` | StatefulSet pod management policy. `Parallel` starts replicas together, which cuts cold-start time on a scale-out. |
| podSecurityContext | object | `{"fsGroup":10000,"runAsGroup":10000,"runAsNonRoot":true,"runAsUser":10000,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level security context. `fsGroup` must match the volume owner for the Trivy cache PVC to be writable. |
| podSpecOverrides | object | `{}` | Deep-merged into the pod spec, for fields the chart does not template (`runtimeClassName`, `hostNetwork`, `enableServiceLinks`, `nodeName`, `shareProcessNamespace`, `readinessGates`). Yours wins on conflict. |
| priorityClassName | string | `""` | PriorityClass for the adapter pods. |
| probes | object | `{"liveness":{"failureThreshold":10,"httpGet":{"path":"/probe/healthy","port":"api-server"},"periodSeconds":10,"timeoutSeconds":3},"readiness":{"failureThreshold":3,"httpGet":{"path":"/probe/ready","port":"api-server"},"periodSeconds":10,"timeoutSeconds":3},"startup":{"failureThreshold":30,"httpGet":{"path":"/probe/healthy","port":"api-server"},"periodSeconds":2,"timeoutSeconds":3}}` | Container probes, passed through verbatim. The chart fills in `scheme: HTTPS` when `api.tls.enabled` is set and no scheme is given. Set a probe to `null` to drop it. |
| proxy.httpProxy | string | `""` | HTTP proxy URL. |
| proxy.httpsProxy | string | `""` | HTTPS proxy URL. |
| proxy.noProxy | string | `""` | Comma-separated hosts the proxy settings do not apply to. Redis and the Harbor registry normally belong here. |
| redis.existingSecret | string | `""` | Existing Secret holding the complete Redis URL. Wins over `url` and keeps the password out of the pod spec. |
| redis.existingSecretKey | string | `"url"` | Key within `redis.existingSecret`. |
| redis.pool.connectionTimeout | string | `"1s"` | Connection timeout. |
| redis.pool.idleTimeout | string | `"5m"` | Idle connection lifetime. `0` keeps idle connections open forever. |
| redis.pool.maxActive | int | `5` | Maximum connections allocated by the pool. |
| redis.pool.maxIdle | int | `5` | Maximum idle connections kept in the pool. |
| redis.pool.readTimeout | string | `"1s"` | Read timeout for a single command reply. |
| redis.pool.writeTimeout | string | `"1s"` | Write timeout for a single command. |
| redis.url | string | `"redis://harbor-harbor-redis:6379"` | Redis URL. Supports a standalone server (`redis://[:password@]host:port/db`) and Sentinel (`redis+sentinel://[:password@]host1:port1,host2:port2/monitor/db`). A password inlined here lands in the pod spec in clear text - use `existingSecret` instead. |
| replicaCount | int | `1` | Number of adapter replicas. Each replica keeps its own Trivy DB cache volume; scale for scan throughput, not for availability of the API. |
| resources | object | `{"limits":{"memory":"1Gi"},"requests":{"cpu":"200m","memory":"512Mi"}}` | Resource requests and limits. The defaults fit a single-worker adapter scanning ordinary images; raise memory before raising `jobQueue.workerConcurrency`, because each concurrent scan runs its own Trivy process holding the vulnerability DB in memory. |
| revisionHistoryLimit | int | `10` | StatefulSet revision history retained for rollbacks. |
| schedulerName | string | `""` | Alternative scheduler for the adapter pods. |
| secret | object | `{}` | Same notation as `config`, rendered into a chart-managed Secret instead, so the values never appear in the pod spec. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true}` | Container-level security context. The adapter writes only to the cache volume and to `/tmp`, both mounted, so the root filesystem stays read-only. |
| service.annotations | object | `{}` | Annotations for the Service. |
| service.clusterIP | string | `""` | Static cluster IP. |
| service.externalTrafficPolicy | string | `""` | External traffic policy. |
| service.ipFamilies | list | `[]` | IP families for the Service, e.g. `[IPv4, IPv6]`. Empty follows the cluster default. |
| service.ipFamilyPolicy | string | `""` | IP family policy: `SingleStack`, `PreferDualStack` or `RequireDualStack`. |
| service.labels | object | `{}` | Labels for the Service. |
| service.loadBalancerSourceRanges | list | `[]` | Load balancer source ranges. |
| service.nodePort | string | `""` | NodePort, when `service.type` is `NodePort` or `LoadBalancer`. |
| service.port | int | `8080` | Service port. Also the port the adapter listens on. |
| service.sessionAffinity | string | `""` | Session affinity. |
| service.type | string | `"ClusterIP"` | Service type. |
| serviceAccount.annotations | object | `{}` | Annotations for the created ServiceAccount (IRSA, Workload Identity). |
| serviceAccount.automountServiceAccountToken | bool | `false` | Mount the ServiceAccount token into the pod. The adapter never calls the Kubernetes API, so this stays off. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount for the adapter. |
| serviceAccount.name | string | the fullname template | Name of the ServiceAccount to use. |
| sidecars | list | `[]` | Sidecar containers, passed through `tpl`. |
| statefulSetAnnotations | object | `{}` | Annotations on the StatefulSet object itself (not its pods). For controllers that key off the workload, such as Argo CD sync waves. Pod annotations are `podAnnotations`; annotations for every object are `commonAnnotations`. |
| statefulSetSpecOverrides | object | `{}` | Deep-merged into the StatefulSet `.spec`, for fields the chart does not template (`minReadySeconds`, `persistentVolumeClaimRetentionPolicy`, `ordinals`). Yours wins on conflict. |
| store.redisNamespace | string | `"harbor.scanner.trivy:data-store"` | Key namespace for scan jobs and reports. |
| store.redisScanJobTTL | string | `2 * trivy.timeout + 3s` | TTL for persisted scan jobs and reports. |
| terminationGracePeriodSeconds | int | `60` | Grace period for a terminating pod. An in-flight Trivy scan is bounded by `trivy.timeout`; a longer grace period lets it finish instead of being killed. |
| tolerations | list | `[]` | Tolerations for pod assignment. |
| topologySpreadConstraints | list | `[]` | Topology spread constraints. |
| trivy.cacheBackend | string | `"fs"` | Where Trivy keeps its per-layer scan cache: `fs`, `memory`, or a `redis://` / `rediss://` URL. `fs` is a single BoltDB file that one process may open at a time, so `jobQueue.workerConcurrency` above 1 needs `memory` or Redis. Sentinel URLs are not accepted here; Trivy dials one node. |
| trivy.cacheDir | string | `"/home/scanner/.cache/trivy"` | Trivy cache directory. Must sit under the mounted cache volume. |
| trivy.cacheMaxSize | string | `"3GiB"` | Size cap for the on-disk scan cache (`fs` only). The cache has no eviction and never shrinks, so once it is over the cap the adapter drops it whole, after the running scan. `0` disables the cap. Keep it under `persistence.size` minus the Trivy DBs (~1Gi) and the reports directory. |
| trivy.cacheRedisCACert | string | `""` | CA certificate for a Redis scan cache, as a path inside the container; mount it with `extraVolumes`/`extraVolumeMounts`. CA, cert and key are required together. |
| trivy.cacheRedisCert | string | `""` | Client certificate for a Redis scan cache (path inside the container). |
| trivy.cacheRedisKey | string | `""` | Client private key for a Redis scan cache (path inside the container). |
| trivy.cacheRedisTLS | bool | `false` | Use TLS with public certificates for a Redis scan cache. |
| trivy.cacheTTL | string | `"168h"` | Expiry for Redis scan cache keys. Required with a Redis backend, where it is the only thing bounding the cache. Ignored by the other backends. |
| trivy.dbRepository | string | `"ghcr.io/aquasecurity/trivy-db"` | OCI repository serving the Trivy vulnerability DB. |
| trivy.debugMode | string | `true` when `logLevel` is `debug`/`trace`, `false` otherwise | Trivy debug mode. |
| trivy.existingIgnorePolicyConfigMap | string | `""` | Existing ConfigMap holding the Rego policy. Wins over `ignorePolicy`. |
| trivy.existingSecret | string | `""` | Existing Secret holding the GitHub token. Wins over `gitHubToken`. |
| trivy.existingSecretKey | string | `"gitHubToken"` | Key within `trivy.existingSecret`. |
| trivy.gitHubToken | string | `""` | GitHub token used for Trivy DB downloads, stored in a chart-managed Secret. Anonymous downloads are rate limited to 60 requests/hour. Prefer `existingSecret` outside throwaway installs. |
| trivy.ignorePolicy | string | `""` | Rego policy filtering scan results, rendered into a chart-managed ConfigMap. See <https://trivy.dev/latest/docs/configuration/filtering/>. |
| trivy.ignorePolicyKey | string | `"policy.rego"` | Key within the ignore-policy ConfigMap. |
| trivy.ignoreUnfixed | bool | `false` | Report only vulnerabilities with a known fix. |
| trivy.insecure | bool | `false` | Skip TLS verification against the scanned registry. |
| trivy.javaDBRepository | string | `"ghcr.io/aquasecurity/trivy-java-db"` | OCI repository serving the Trivy Java DB. |
| trivy.offlineScan | bool | `false` | Disable external API calls used to identify dependencies. |
| trivy.reportsDir | string | `"/home/scanner/.cache/reports"` | Trivy reports directory. Must sit under the mounted cache volume. |
| trivy.securityChecks | string | `"vuln"` | Comma-separated Trivy scanners (`SCANNER_TRIVY_SECURITY_CHECKS`), e.g. `vuln` or `vuln,secret`. |
| trivy.severity | string | `"UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"` | Comma-separated severities to report. |
| trivy.skipJavaDBUpdate | bool | `false` | Skip Java DB downloads. Enable only when you mount a pre-populated `trivy-java.db` at `<cacheDir>/java-db/trivy-java.db`. |
| trivy.skipUpdate | bool | `false` | Skip Trivy DB downloads. Enable only when you mount a pre-populated `trivy.db` at `<cacheDir>/db/trivy.db`. |
| trivy.skipVEXRepoUpdate | bool | `false` | Skip updating the VEX repository. |
| trivy.timeout | string | `"5m0s"` | Time budget for a single scan. Also sets the default scan job TTL (`2 * timeout + 3s`) when `store.redisScanJobTTL` is unset. |
| trivy.useSBOMAccessory | bool | `false` | Serve scans from a pre-existing SBOM accessory attached to the image instead of re-scanning its layers. |
| trivy.vexSource | string | `""` | VEX source used to filter vulnerabilities: `oci` or `repo`. |
| trivy.vulnType | string | `"os,library"` | Comma-separated vulnerability types: `os`, `library`. |
| updateStrategy | object | `{}` | StatefulSet update strategy. Empty means the Kubernetes default (`RollingUpdate`). |
