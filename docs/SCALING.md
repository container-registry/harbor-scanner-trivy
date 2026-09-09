# Scaling scan throughput

Run **one worker per adapter pod**, increase replicas, and share image/layer analysis through a **dedicated Redis/Valkey instance**. Each pod must own its writable local Trivy database directory. The adapter rejects `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` values other than `1`, even with Redis analysis caching: vulnerability and Java databases still live locally.

## Connections and storage

| Data | Connection/storage | Retention |
| --- | --- | --- |
| Accepted jobs, deliveries, ownership, reports | Existing `SCANNER_REDIS_URL` (Helm `redis.*`) | Unacknowledged work persists; completed jobs/reports expire after acknowledgement |
| Trivy image/layer analysis (`fanal::*`) | `SCANNER_TRIVY_CACHE_BACKEND` (Helm `trivy.cacheBackend`), dedicated instance | Positive TTL, set on writes; instance memory budget and eviction |
| Vulnerability and Java databases, temporary files | Separate local volume per pod | Managed by Trivy; size pod disk and memory for scans and DB updates |

The job backend requires Redis 6.2+ (for `XAUTOCLAIM`) or compatible Valkey. Startup checks command availability before opening the API; its ACL needs `COMMAND INFO` as well as Streams, string, expiry and Lua commands. Integration tests exercise Redis 7.4 and Valkey 8.1 with authentication and mutual TLS. The Trivy analysis-cache client supports `redis://` and adapter-normalized `rediss://`, not Sentinel or Redis Cluster endpoints. The existing job connection still supports Sentinel.

Enable the optional dedicated Valkey subchart (`valkey.enabled: true`) or provision an external analysis cache separately from Harbor's Redis/Valkey. The dependency is the same official chart and version as Harbor-next: `valkey` 0.9.3 from `oci://ghcr.io/valkey-io/valkey-helm`. A different logical database number provides no independent `maxmemory`, eviction policy, CPU or failure isolation. Keep operational job storage on a non-evicting instance with persistence/replication appropriate to the required durability. Streams survive client disconnects and worker restarts; surviving a Redis server failure also depends on Redis persistence and failover configuration. Accepted backlog consumes storage until it completes, so monitor and limit submission rates when workers cannot keep up.

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

Use `rediss://` or `trivy.cacheRedisTLS: true` for TLS with system trust roots. Trivy 0.74.0 requires CA, client certificate and key together when supplying custom certificate files. For mutual TLS, add:

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

Merge these settings into one values file rather than repeating the `trivy` mapping. Allow network egress to both backends, registry and database mirrors. Cache credentials are passed to Trivy through its environment and redacted from its returned diagnostics. Startup logs show the effective cache type and TTL. Use the adapter's `SCANNER_TRIVY_CACHE_*` settings: they override inherited native `TRIVY_*` cache variables. Invalid URLs, incomplete TLS inputs and non-positive Redis TTLs fail validation; errors do not silently select filesystem caching.

## Cache budget and reuse

Configure the dedicated instance's `maxmemory` and a cache eviction policy such as `allkeys-lru`; the bundled subchart defaults to `maxmemory 512mb`, `allkeys-lru`, a 1 GiB container limit, and disabled snapshots/AOF. Change `valkey.valkeyConfig` and `valkey.resources` together when sizing it. The subchart is disabled by default; its upstream persistence, ACL and TLS values pass through under `valkey`. Reserve memory beyond `maxmemory` for process/allocator overhead, clients, replication buffers and persistence overhead. A pod/container memory limit equal to `maxmemory` leaves insufficient headroom. Check [Valkey's eviction guidance](https://valkey.io/topics/lru-cache/).

Choose a positive TTL longer than the expected rescan interval with margin. Reads do not renew the TTL, and eviction can remove entries earlier. Expired entries are analyzed again. If entries disappear during a scan, or the cache cannot accept writes, the scan may need a retry. A budget too small for the working set causes repeated analysis and lower throughput; it is not solved by adding workers. `trivy.cacheMaxSize` is deprecated and ignored: no filesystem cache size cap was implemented.

Redis RAM is **not equal to `fanal.db` disk size**. Both contain analyzed image/layer metadata rather than registry blobs, but BoltDB files include pages and reusable free space while Redis adds key/object/allocator overhead. TTL and eviction change the retained working set, and replicas/persistence change total deployment consumption. Unique scanned layers, analyzer output and scan history matter more than registry size. Trivy's cache values are JSON; the adapter's report gzip compression does not apply to them. Measure Redis `used_memory`, peak/RSS, evictions, hits/misses and sampled key sizes; there is no fixed disk-to-RAM conversion. Historical details are in [the cache analysis](WORKER_CACHE_ANALYSIS.md).

For vulnerability rescans, `trivy.useSBOMAccessory: true` can reuse compatible Harbor SBOM accessories generated by this adapter. Generate and retain those SBOMs first; enabling reuse does not generate them. Missing, invalid or unusable accessories fall back to full-image analysis. Existing non-vulnerability scanner behavior is preserved; see [Performance](../README.md#performance).

## Delivery and shutdown

The enqueuer atomically records each job and its stream delivery before accepting it. Pods share a consumer group and execute one attempt at a time. A one-minute lease is renewed every 20 seconds. Lua checks ownership on status/report writes and acknowledgement, fencing a stale worker after ownership changes.

An interrupted attempt stays pending. Another pod reclaims it after its idle lease window, checks completion, and resumes if needed. Shutdown cancels the active Trivy subprocess and leaves its delivery recoverable. The chart's default pre-stop hook keeps HTTP serving for ten seconds while Kubernetes removes the terminating pod from Service endpoints; this prevents report polls from reaching an already closed listener during ordinary endpoint propagation. Custom `lifecycle.preStop` hooks replace that delay and must allow equivalent draining. Completed but unacknowledged work retains its completion record, so recovery can acknowledge it without rescanning. Acknowledgement deletes the stream entry and starts `SCANNER_STORE_REDIS_SCAN_JOB_TTL` on job/report keys. Queue wait and execution do not consume that retention window.

Delivery is **at least once**, not exactly once: a crash after scanning but before saving completion can repeat analysis. Cache errors, cancellation and persistence interruptions leave work pending. After three started attempts, another recovery marks the job failed with a visible retry-limit error; Harbor can submit it again after the underlying problem is fixed. Ordinary scanner failures become terminal reports immediately. Ownership fencing prevents stale results from replacing newer results; it cannot guarantee zero overlapping computation during network partitions. Do not trim unacknowledged stream entries or delete consumers with pending deliveries.

## Upgrade and rollback

The Streams queue is incompatible with the previous Pub/Sub protocol. A normal rolling upgrade that mixes these versions is unsafe.

1. Stop scheduled/bulk scan submissions and scan-on-push in Harbor, and let its outstanding work drain. Confirm no queued or running adapter jobs remain; stop if drain cannot be verified.
2. Verify the job backend supports Redis Streams recovery and has persistence and capacity configured. Preserve existing job/store namespaces and report retention.
3. Stop all old adapter pods, upgrade the binary and chart together, configure the dedicated cache, and start the new pods. For Helm/GitOps, use a staged scale-to-zero transition rather than mixing queue protocols.
4. Check startup logs and readiness, submit a smoke scan, retrieve its report, then resume submissions.

Old Pub/Sub notifications cannot be replayed automatically. If an earlier outage already stranded old queued work, identify it in Harbor and resubmit it after the upgrade; don't delete operational keys blindly. Historical `fanal.db` entries are not imported into Redis, so the analysis cache initially warms through scans.

Rollback follows the same stop-submissions/drain/stop-all sequence. Confirm the Streams queue is empty before starting an old binary. Configure `fs` and one worker per pod (or settings that the old binary actually supports); old binaries ignore these new adapter cache variables. Preserve completed reports long enough for Harbor to fetch them. Do not mix old workers with outstanding Streams jobs.

## Monitoring and validation

The existing `/metrics` endpoint exports:

- `harbor_scanner_trivy_jobs_in_progress`: active attempts in this pod, at most one.
- `harbor_scanner_trivy_job_attempts_total{outcome="success|failed"}`: observed attempts, including retryable failures; a failed attempt does not necessarily mean a terminally failed job.
- `harbor_scanner_trivy_job_duration_seconds`: attempt latency histogram, including report persistence.
- `harbor_scanner_trivy_scan_retries_total` and `harbor_scanner_trivy_lease_losses_total`: recovery and ownership trouble.
- `harbor_scanner_trivy_queue_unacknowledged_jobs` and `harbor_scanner_trivy_queue_oldest_age_seconds`: shared backlog, including pending scans. Use `max` across pods, not `sum`. These are sampled between scans (at most every ten seconds); busy pods can expose samples as old as their scan timeout.

Pair these with Harbor completion/failure rates, registry transfer metrics, pod CPU/memory/temporary-storage usage and the dedicated cache's memory, eviction, hit/miss and latency statistics. Raising replicas helps only while registry bandwidth, CPU, local storage, job delivery and cache service have spare capacity.

Reproduce the cache tests with Trivy **0.74.0** on `PATH` and Docker available:

```sh
go test -race -v -tags=integration -run TestDedicatedCacheBackends ./test/integration/api
go test -race ./pkg/queue ./pkg/scan ./pkg/trivy ./pkg/etc
go test -tags=integration ./test/integration/...
```

The cache test uses a fixed Alpine image, a small fixture vulnerability DB, independent local directories and an HTTP registry. It asserts identical findings and zero additional layer GETs from two and four warm scanner instances, then verifies eight HTTP-submitted scans through two and four real controllers/workers on each backend. It exercises Redis 7.4 and Valkey 8.1 with password authentication/mutual TLS, TTL expiration, cache eviction/write failure, and recovery after restoring capacity. Queue tests cover concurrent workers, accepted backlog with no workers, cancellation/reclaim, repeated lease renewal, stale-write fencing, retry exhaustion and completion surviving delayed acknowledgement. Lease tests accelerate the lease interval rather than waiting over five minutes.

One local macOS ARM64 run (Trivy 0.74.0, Docker Desktop) measured the following **small-fixture results**, not production capacity:

| Backend | Cold scan | Two warm instances, batch | Four warm instances, batch | Cache peak used memory |
| --- | --- | --- | --- | --- |
| Redis 7.4 | 527 ms | 107 ms (~1,124 scans/min) | 118 ms (~2,038 scans/min) | 1,290,336 bytes |
| Valkey 8.1 | 181 ms | 110 ms (~1,096 scans/min) | 124 ms (~1,931 scans/min) | 1,219,440 bytes |

All warm batches downloaded zero additional image layers and matched baseline findings. These short batches include CLI startup and use preseeded fixture vulnerability databases; they do not establish sustained throughput, production cache size, p50/p95 latency, pod CPU/RSS/temp-storage peaks, cold full-database downloads or refresh behavior. Before choosing production replica counts and memory budgets, measure those dimensions against a representative fixed image set and database version, including long scans, pod termination and cache pressure. No linear speedup or numeric throughput SLA is promised.

Additional acceptance scenarios remain to be validated: an accepted HTTP scan automatically recovering from a real cache connection outage, eviction precisely between cache lookup and layer application, cold/refreshing vulnerability and Java databases, and process-level interruption/recovery during a scan lasting over five minutes. Current tests cover the queue and subprocess cancellation mechanisms separately. Keep these distinctions when assessing readiness for a particular production workload.
