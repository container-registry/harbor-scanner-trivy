# Scaling scan throughput

Run one worker per adapter pod and add replicas to increase throughput. Each pod needs its own writable Trivy database directory because vulnerability and Java databases remain local, even with Redis analysis caching. The adapter rejects `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` values other than `1`. Use a dedicated Redis/Valkey instance to share image/layer analysis across pods.

## Connections and storage

| Data | Connection/storage | Retention |
| --- | --- | --- |
| Accepted jobs, deliveries, ownership, reports | Existing `SCANNER_REDIS_URL` (Helm `redis.*`) | Unacknowledged work persists; completed jobs/reports expire after acknowledgement |
| Trivy image/layer analysis (`fanal::*`) | `SCANNER_TRIVY_CACHE_BACKEND` (Helm `trivy.cacheBackend`), dedicated instance | Positive TTL, set on writes; instance memory budget and eviction |
| Vulnerability and Java databases, temporary files | Separate local volume per pod | Managed by Trivy; size pod disk and memory for scans and DB updates |

The job backend requires Redis 6.2+ (for `XAUTOCLAIM`) or compatible Valkey. Startup checks command availability before opening the API; its ACL needs `COMMAND INFO` as well as Streams, string, expiry and Lua commands. Integration tests exercise Redis 7.4 and Valkey 8.1 with authentication and mutual TLS. The Trivy analysis-cache client supports `redis://` and adapter-normalized `rediss://`, not Sentinel or Redis Cluster endpoints. The existing job connection still supports Sentinel.

Enable the optional dedicated Valkey subchart (`valkey.enabled: true`) or provision an external analysis cache separately from Harbor's Redis/Valkey. The dependency is the same official chart and version as Harbor-next: `valkey` 0.9.3 from `oci://ghcr.io/valkey-io/valkey-helm`. Logical databases share the instance's `maxmemory`, eviction policy and CPU, and fail together. Keep operational job storage on a non-evicting instance with persistence/replication appropriate to the required durability. Streams retain work through client disconnects and worker restarts. Recovery from a Redis server failure depends on its persistence and failover configuration. Accepted jobs use storage until they complete. Monitor the backlog and limit submissions when workers cannot keep up.

## Helm deployment

The chart's default per-pod volume claim templates provide independent database directories. Do not give replicas one shared writable PVC, even with a Redis analysis cache. Start with two replicas and evaluate four against the same workload.

```yaml
replicaCount: 2
podManagementPolicy: Parallel
jobQueue:
  workerConcurrency: 1
valkey:
  enabled: true
trivy:
  cacheTTL: 168h
```

With `valkey.enabled`, the default `fs` backend resolves to the subchart's primary Service. Its release-scoped name keeps it separate from Harbor's existing `valkey` Service; do not override that name to collide. See the [dedicated cache example](../deploy/chart/example/dedicated-cache/) for upstream ACL and TLS configuration. External caches remain supported by disabling the subchart and setting `trivy.cacheBackend` explicitly.

For credentials, provision a Secret `trivy-analysis-cache` with a `url` key containing the full URL, then override the environment entry:

```yaml
extraEnv:
  - name: SCANNER_TRIVY_CACHE_BACKEND
    valueFrom:
      secretKeyRef:
        name: trivy-analysis-cache
        key: url
```

Use `rediss://` or `trivy.cacheRedisTLS: true` to encrypt cache traffic with system trust roots, especially when using credentials. A `redis://` connection without TLS sends credentials and cache data in plaintext; use it only within a trusted, isolated network or when transport encryption is provided separately. Trivy 0.74.0 requires CA, client certificate and key together when supplying custom certificate files. For mutual TLS, add:

```yaml
trivy:
  cacheTTL: 168h
  cacheRedisTLS: true
  cacheRedisCACert: /etc/trivy-cache/ca.crt
  cacheRedisCert: /etc/trivy-cache/tls.crt
  cacheRedisKey: /etc/trivy-cache/tls.key
extraVolumes:
  - name: trivy-cache-tls
    secret:
      secretName: trivy-analysis-cache-tls
extraVolumeMounts:
  - name: trivy-cache-tls
    mountPath: /etc/trivy-cache
    readOnly: true
```

Merge these settings under a single `trivy` mapping in your values file. Allow network egress to both backends and the registry and database mirrors. With `networkPolicy.egressEnabled: true`, add the bundled cache to `networkPolicy.egress` as well; enabling the subchart does not add a rule. Allow the cache pods in the same namespace on the configured Valkey port, and allow DNS resolution. The adapter passes cache credentials through Trivy's environment and redacts them from returned diagnostics. Startup logs show the cache type and TTL.

Use `SCANNER_TRIVY_CACHE_*` to configure the adapter; these settings override inherited native `TRIVY_*` cache variables. Validation rejects invalid URLs, incomplete TLS inputs and non-positive Redis TTLs. A configuration error stops startup instead of selecting filesystem caching.

## Cache budget and reuse

Configure the dedicated instance's `maxmemory` and a cache eviction policy such as `allkeys-lru`; the bundled subchart defaults to `maxmemory 512mb`, `allkeys-lru`, a 1 GiB container limit, and disabled snapshots/AOF. Change `valkey.valkeyConfig` and `valkey.resources` together when sizing it. The subchart is disabled by default; its upstream persistence, ACL and TLS values pass through under `valkey`.

Reserve memory beyond `maxmemory` for process/allocator overhead, clients, replication buffers and persistence overhead. Set the pod/container memory limit above `maxmemory` to leave that headroom. Check [Valkey's eviction guidance](https://valkey.io/topics/lru-cache/).

Choose a positive TTL longer than the expected rescan interval with margin. Reads do not renew the TTL, and eviction can remove entries earlier. Expired entries are analyzed again. If entries disappear during a scan, or the cache cannot accept writes, the scan may need a retry. An undersized cache causes repeated analysis and lowers throughput, even if you add workers. `trivy.cacheMaxSize` is deprecated and ignored: no filesystem cache size cap was implemented.

The size of `fanal.db` does not predict Redis RAM usage. Both store analyzed image/layer metadata, excluding registry blobs. BoltDB files include pages and reusable free space; Redis adds key, object and allocator overhead. TTL and eviction change the retained working set, and replicas/persistence change total deployment consumption. Unique scanned layers, analyzer output and scan history matter more than registry size. Trivy's cache values are JSON; the adapter's report gzip compression does not apply to them. Measure Redis `used_memory`, peak/RSS, evictions, hits/misses and sampled key sizes; there is no fixed disk-to-RAM conversion. Historical details are in [the cache analysis](WORKER_CACHE_ANALYSIS.md).

For vulnerability rescans, `trivy.useSBOMAccessory: true` can reuse compatible Harbor SBOM accessories generated by this adapter. Generate and retain those SBOMs first; enabling reuse does not generate them. Missing, invalid or unusable accessories fall back to full-image analysis. Existing non-vulnerability scanner behavior is preserved; see [Scaling scan throughput](../README.md#scaling-scan-throughput).

## Delivery and shutdown

Before accepting a job, the enqueuer atomically saves the job and its stream delivery. Pods share a consumer group, with one active attempt per pod. Each worker renews its one-minute lease every 20 seconds. Lua checks ownership before saving status or reports and before acknowledging delivery, so a worker that has lost ownership cannot write stale results.

An interrupted attempt stays pending. Another pod reclaims it after its idle lease window, checks completion, and resumes if needed. Shutdown cancels the active Trivy subprocess and leaves its delivery recoverable.

The chart's default pre-stop hook keeps HTTP serving for ten seconds while Kubernetes removes the terminating pod from Service endpoints; this prevents report polls from reaching an already closed listener during ordinary endpoint propagation. Custom `lifecycle.preStop` hooks replace that delay and must allow equivalent draining.

Completed but unacknowledged work retains its completion record, so recovery can acknowledge it without rescanning. Acknowledgement deletes the stream entry and starts `SCANNER_STORE_REDIS_SCAN_JOB_TTL` on job/report keys. Queue wait and execution do not consume that retention window.

Delivery is at least once. A crash between scanning and saving completion can cause another worker to repeat the analysis. Cache errors, cancellation and persistence interruptions leave work pending. After three started attempts, another recovery marks the job failed with a visible retry-limit error. Harbor can submit it again after the underlying problem is fixed. Ordinary scanner failures become terminal reports immediately. Ownership fencing prevents stale results from replacing newer results; it cannot guarantee zero overlapping computation during network partitions. Do not trim unacknowledged stream entries or delete consumers with pending deliveries.

Malformed deliveries are moved out of the active stream into the `<stream>:quarantine` Redis hash, keyed by their original delivery ID. The original fields are retained without expiry for inspection; they can contain registry credentials, so treat them as secrets. Investigate any nonzero `harbor_scanner_trivy_queue_quarantined_jobs` value. After correcting the cause and resubmitting any affected scan through Harbor, an operator can remove the inspected hash entry. If quarantine storage fails, the original delivery remains recoverable. Storage errors before an attempt starts do not consume the three-attempt scan limit.

## Upgrade and rollback

The Streams queue is incompatible with the previous Pub/Sub protocol. A normal rolling upgrade that mixes these versions is unsafe.

1. Stop scheduled/bulk scan submissions and scan-on-push in Harbor, and let its outstanding work drain. Confirm no queued or running adapter jobs remain; stop if drain cannot be verified.
2. Verify the job backend supports Redis Streams recovery and has persistence and capacity configured. Preserve existing job/store namespaces and report retention.
3. Stop all old adapter pods, upgrade the binary and chart together, configure the dedicated cache, and start the new pods. For Helm/GitOps, use a staged scale-to-zero transition to keep the queue protocols separate.
4. Check startup logs and readiness, submit a smoke scan, retrieve its report, then resume submissions.

Old Pub/Sub notifications cannot be replayed automatically. If an earlier outage already stranded old queued work, identify it in Harbor and resubmit it after the upgrade; don't delete operational keys blindly. Historical `fanal.db` entries are not imported into Redis, so the analysis cache initially warms through scans.

Rollback follows the same stop-submissions/drain/stop-all sequence. Confirm the Streams queue is empty before starting an old binary. Configure `fs` and one worker per pod (or settings that the old binary actually supports); old binaries ignore these new adapter cache variables. Preserve completed reports long enough for Harbor to fetch them. Do not mix old workers with outstanding Streams jobs.

## Monitoring and validation

The existing `/metrics` endpoint exports:

- `harbor_scanner_trivy_jobs_in_progress`: active attempts in this pod, at most one.
- `harbor_scanner_trivy_job_attempts_total{outcome="success|failed"}`: observed attempts, including retryable failures; a failed attempt does not necessarily mean a terminally failed job.
- `harbor_scanner_trivy_job_duration_seconds`: attempt latency histogram, including report persistence.
- `harbor_scanner_trivy_scan_retries_total` and `harbor_scanner_trivy_lease_losses_total`: recovery and ownership trouble.
- `harbor_scanner_trivy_queue_unacknowledged_jobs` and `harbor_scanner_trivy_queue_oldest_age_seconds`: shared backlog, including pending scans. Use `max` across pods; `sum` would count the shared queue once per replica. These are sampled between scans (at most every ten seconds); busy pods can expose samples as old as their scan timeout.

Pair these with Harbor completion/failure rates, registry transfer metrics, pod CPU/memory/temporary-storage usage and the dedicated cache's memory, eviction, hit/miss and latency statistics. Raising replicas helps only while registry bandwidth, CPU, local storage, job delivery and cache service have spare capacity.

Reproduce the cache tests with Trivy 0.74.0 on `PATH` and Docker available:

```sh
go test -race -v -tags=integration -run TestDedicatedCacheBackends ./test/integration/api
go test -race ./pkg/queue ./pkg/scan ./pkg/trivy ./pkg/etc
go test -tags=integration ./test/integration/...
```

The cache test uses a fixed Alpine image, a small fixture vulnerability DB, independent local directories and an HTTP registry. It asserts identical findings and zero additional layer GETs from two and four warm scanner instances, then verifies eight HTTP-submitted scans through two and four real controllers/workers on each backend. It exercises Redis 7.4 and Valkey 8.1 with password authentication/mutual TLS, TTL expiration, cache eviction/write failure, and recovery after restoring capacity.

Queue tests cover concurrent workers, accepted backlog with no workers, cancellation/reclaim, repeated lease renewal, stale-write fencing, retry exhaustion and completion surviving delayed acknowledgement. Lease tests use an accelerated interval to avoid waits of more than five minutes.

The following measurements come from one local macOS ARM64 run with Trivy 0.74.0 and Docker Desktop, using the small fixture described above:

| Backend | Cold scan | Two warm instances, batch | Four warm instances, batch | Cache peak used memory |
| --- | --- | --- | --- | --- |
| Redis 7.4 | 527 ms | 107 ms (~1,124 scans/min) | 118 ms (~2,038 scans/min) | 1,290,336 bytes |
| Valkey 8.1 | 181 ms | 110 ms (~1,096 scans/min) | 124 ms (~1,931 scans/min) | 1,219,440 bytes |

All warm batches downloaded zero additional image layers and matched baseline findings. These short batches include CLI startup and use preseeded fixture vulnerability databases; they do not establish sustained throughput, production cache size, p50/p95 latency, pod CPU/RSS/temp-storage peaks, cold full-database downloads or refresh behavior. Before choosing production replica counts and memory budgets, measure those dimensions against a representative fixed image set and database version, including long scans, pod termination and cache pressure. The results do not establish linear scaling or a throughput SLA.

The following acceptance scenarios still need testing: an accepted HTTP scan automatically recovering from a real cache connection outage, eviction precisely between cache lookup and layer application, cold/refreshing vulnerability and Java databases, and process-level interruption/recovery during a scan lasting over five minutes. Current tests cover queue recovery and subprocess cancellation separately. These gaps matter when deciding whether the adapter is ready for a particular production workload.
