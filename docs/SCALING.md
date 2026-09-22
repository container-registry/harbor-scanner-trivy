# Scaling scan throughput

This guide explains what limits scan throughput, which settings change it, and
which signals tell you what to change next. For a working values file, start
from the [high-throughput example](../deploy/chart/example/high-throughput/).
Metric definitions are in the [metrics catalog](metrics.md) and the panels in
the [dashboard guide](../deploy/chart/dashboards/README.md).

Sections: [How scaling works](#how-scaling-works) and [Background](#background)
explain; [Tuning levers](#tuning-levers), [Monitoring](#monitoring),
[Configuration reference](#configuration-reference) and
[Upgrade and rollback](#upgrade-and-rollback) are reference.

## How scaling works

### One worker per pod, more pods

Each adapter pod runs exactly one worker, and each worker runs one Trivy
process at a time. Throughput scales by adding pods, not workers:
`jobQueue.workerConcurrency` (`SCANNER_JOB_QUEUE_WORKER_CONCURRENCY`) must be
`1`, and the adapter and chart reject other values. Two Trivy processes in one
pod would contend for the BoltDB lock on the local analysis cache
(`fanal.db`), and vulnerability database updates are local to the pod anyway.

Every pod keeps its own PVC for the vulnerability database, Java index and
temporary files. Never share one writable PVC between replicas.

A scan passes through these stages:

1. Harbor's jobservice picks an `IMAGE_SCAN` task and calls the adapter's `POST /api/v1/scan`.
2. The adapter stores the job and appends it to a Redis Stream, then returns `202`.
3. A free worker in any pod claims the delivery and runs Trivy.
4. The worker stores the report; Harbor polls `GET /api/v1/scan/{id}/report` until it gets it.

### Two Redis instances

A single pod needs one Redis. Several pods that should share Trivy's image
analysis need a second, separate instance. They hold different data and must
not be merged: the cache evicts keys, the job store must not.

|  | Job store | Analysis cache |
| --- | --- | --- |
| Required | Always | Only to share analysis across pods; without it each pod analyzes into its own `fanal.db` |
| Typically | Harbor's existing Redis/Valkey (default `redis://harbor-harbor-redis:6379`) | Bundled Valkey (`valkey.enabled: true`) or an external instance |
| Helm values | `redis.*` | `valkey.*`, or `trivy.cacheBackend` for an external one |
| Stores | Queued scans, leases, job state, reports until Harbor fetches them | Trivy image/layer analysis (`fanal::*` keys) |
| If its data is lost | Queued scans and unfetched reports are lost; resubmit from Harbor | Images are analyzed again: slower, nothing lost |
| Eviction | Must be off | Expected (`allkeys-lru`) |
| Server | Redis 6.2+ or Valkey; Sentinel supported | `redis://` or `rediss://`; no Sentinel, no Cluster |

A different logical database number on Harbor's instance is not a separate
instance: logical databases share `maxmemory`, the eviction policy and CPU, and
fail together.

With a shared cache, a layer analyzed by one pod is neither downloaded nor
analyzed again by the others.

### What limits throughput

The ceilings apply in this order. Adding adapter pods only helps once the
earlier ones are raised.

1. **Harbor jobservice workers.** Harbor runs at most `max_job_workers` jobs at
   once, scans included (harbor-helm `jobservice.maxJobWorkers`, default 10;
   harbor-next-helm `jobservice.max_job_workers`, default 4). Each scan holds a
   worker until Harbor has fetched the report, and most of that time is Harbor's
   report polling interval, not scanning. In one production installation with 4
   jobservice workers, a scan-all ran at 50 to 75 scans/min with anywhere from 1
   to 10 adapter pods.
2. **Harbor's PostgreSQL.** Every scan task writes to Harbor's database. When
   the jobservice pool is raised, database CPU and connections become the next
   limit, together with any other Harbor sharing that database.
3. **Adapter pods.** Once Harbor delivers faster than the workers finish, the
   adapter queue grows and more pods help, as long as CPU, memory, registry
   bandwidth, local disk and the analysis cache have headroom.

## Tuning levers

| Lever | Setting | Effect | Cost and caveats |
| --- | --- | --- | --- |
| Harbor scan concurrency | Harbor `jobservice.maxJobWorkers` / `max_job_workers` | Raises the first ceiling | More load on Harbor's PostgreSQL; raise in steps |
| Adapter pods | `replicaCount`, `podManagementPolicy: Parallel` | One more concurrent scan per pod | Each new pod creates a PVC and downloads the vulnerability DB once |
| Autoscaling | `autoscaling.*` (CPU-based HPA) | Pods follow load | Scale-down cancels the pod's running scan; another pod recovers it |
| Pod resources | `resources`, `trivy.childGoMemLimit` | Fewer OOM kills and less CPU throttling on large images | Raise memory before replicas; the Trivy child gets 80% of the memory limit as its soft heap limit by default |
| Shared analysis cache | `valkey.enabled` or `trivy.cacheBackend` | Pods reuse each other's layer analysis | One more instance to run |
| Cache capacity and TTL | `valkey.valkeyConfig` (`maxmemory`), `valkey.resources`, `trivy.cacheTTL` | Fewer re-analyses | Memory; see [Analysis cache sizing](#analysis-cache-sizing) |
| SBOM reuse | `trivy.useSBOMAccessory: true` | Rescans reuse SBOMs this adapter generated before, skipping image analysis | Requires those SBOM accessories to exist; otherwise falls back to a full scan |
| Local volume | `persistence.size` (default `5Gi`) | Room for databases and unpacked images | Too small fails scans on large images |
| Scan timeout | `trivy.timeout` (default `5m0s`) | Long scans finish instead of failing | A stuck scan holds its pod longer; also sets default report retention (`2 * timeout + 3s`) |
| Job store pool | `redis.pool.maxActive` (default `5`) | Fewer waits for a Redis connection | Only if pool timeouts appear |

Scaling a StatefulSet down keeps the removed pods' PVCs. To delete them
automatically, set `persistentVolumeClaimRetentionPolicy` through
`statefulSetSpecOverrides`.

## Monitoring

The Trivy dashboard shows every signal below; the Valkey dashboard covers the
analysis cache. Adapter metric names omit the `harbor_scanner_trivy_` prefix.
Start from the symptom:

| Symptom | Signal | Change |
| --- | --- | --- |
| Harbor's scan queue grows while adapter workers are idle | `harbor_task_queue_size` / `harbor_task_queue_latency{type="IMAGE_SCAN"}` high, `jobs_in_progress` 0 | Harbor jobservice workers |
| Harbor database saturated during scan-all | PostgreSQL CPU and connections (outside this dashboard) | Stop raising jobservice workers |
| Adapter backlog grows, all workers busy | `queue_oldest_age_seconds` and `queue_unacknowledged_jobs` rising, `jobs_in_progress` 1 on every pod | Add pods |
| Scans slow on busy pods | CPU throttling panel, `job_duration_seconds` p95 | CPU requests, or more pods |
| OOM kills or restarts | Last termination was OOM, `subprocess_max_rss_bytes` near the limit | `resources.limits.memory` |
| Pods re-analyze the same layers | Cache hit rate low, `redis_evicted_keys_total` rising, memory at `maxmemory` | Cache `maxmemory` and `valkey.resources`, or `trivy.cacheTTL` |
| Disk running out | `storage_available_bytes`, estimated time to full | `persistence.size` |
| Waiting on the job store | `redis_pool_timeouts_total`, pool wait time | `redis.pool.maxActive` |
| Work stuck while workers idle | `queue_oldest_age_seconds` rising with `jobs_in_progress` 0 everywhere | See queue health below |

Queue health:

- Every pod reports the same shared queue: aggregate queue metrics with `max`,
  not `sum`. If they are missing, check `queue_collection_success` and
  `queue_collection_errors_total`.
- `ready{check=~"queue|worker|binary"}` mirrors `/probe/ready`. A pod turns
  unready when the job store is unreachable, its consumer group is gone, the
  worker loop has stalled for three lease periods, or the Trivy binary is
  missing. Database freshness, disk space and the analysis cache are deliberately
  excluded: an unready pod leaves the Service, and Harbor would report a
  scan-all against it as successful with zero scans. Alert on those separately.
- `queue_group_recreated_total` rises after the job store restarted without
  persistence. Workers resume, but lost deliveries must be resubmitted from Harbor.
- `queue_quarantined_jobs` above zero means undeliverable jobs; see
  [Quarantine](#quarantine).
- `job_attempts_total{outcome="failed"}` counts attempts, including ones that
  are retried; it is not the number of failed scans.

## Configuration reference

### Job store

- Redis 6.2+ (`XAUTOCLAIM`) or Valkey, standalone or Sentinel.
- Eviction off, persistence and replication matching the durability you need.
  Accepted jobs never expire, so memory grows with the backlog; limit submissions
  when workers cannot keep up.
- Pass the URL through `redis.existingSecret` so the password stays out of the pod spec.
- A restricted ACL user needs `COMMAND INFO`, Streams, string, expiry and Lua
  commands, plus `HSET` and `HLEN`. The adapter checks them at startup, before
  opening the API.

Never trim unacknowledged stream entries or delete consumers with pending
deliveries.

### Analysis cache

**Bundled Valkey.** `valkey.enabled: true` deploys the official `valkey` chart
0.9.3 from `oci://ghcr.io/valkey-io/valkey-helm`, the same as Harbor-next. The
default `trivy.cacheBackend: fs` then resolves to the subchart's primary
Service. Its release-scoped name keeps it apart from Harbor's own `valkey`
Service; do not override it into a collision. Upstream values pass through
under `valkey`. Defaults: `maxmemory 512mb`, `allkeys-lru`, 1 GiB container
limit, no snapshots or AOF.

**External instance.** Keep `valkey.enabled: false` and set
`trivy.cacheBackend` to its URL. With credentials, put the full URL in a Secret
and override the environment variable:

```yaml
extraEnv:
  - name: SCANNER_TRIVY_CACHE_BACKEND
    valueFrom:
      secretKeyRef:
        name: trivy-analysis-cache
        key: url
```

**Bundled Valkey with authentication.** Put the ACL password under `default`
and the URL-encoded credential URL under `url` in the same Secret, and keep the
`extraEnv` override above. For release `scanner` the URL is
`redis://default:<encoded-password>@scanner-valkey:6379/0`. Helm rejects
`valkey.auth.enabled` without the override and never generates the password.

```yaml
valkey:
  enabled: true
  auth:
    enabled: true
    usersExistingSecret: trivy-analysis-cache
    aclUsers:
      default:
        permissions: "~* &* +@all"
```

**TLS.** Use `rediss://` or `trivy.cacheRedisTLS: true` for system trust roots.
Without TLS, credentials and cache data cross the network in plaintext. For a
private CA or mutual TLS, Trivy 0.74.0 needs CA, certificate and key together:

```yaml
trivy:
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

Helm checks the trio at render time when it comes from these settings or three
named `extraEnv` entries; through `extraEnvFrom` it cannot, and the adapter
validates it at startup instead.

**Validation.** `SCANNER_TRIVY_CACHE_*` wins over inherited `TRIVY_*` variables.
Invalid URLs, incomplete TLS inputs and a non-positive TTL stop startup instead
of falling back to the filesystem cache. Startup logs show the cache type and
TTL, never the URL.

### Analysis cache sizing

- Keep the container memory limit above `maxmemory` for allocator, client and
  replication overhead, and change `valkey.valkeyConfig` and `valkey.resources`
  together. See [Valkey's eviction guidance](https://valkey.io/topics/lru-cache/).
- Set `trivy.cacheTTL` above your rescan interval with margin. The TTL is set on
  write and not renewed by reads; eviction can remove entries earlier.
- An undersized cache means repeated analysis and lower throughput however many
  pods run. Size by measurement: `used_memory`, evictions and hit rate on the
  Valkey dashboard. `fanal.db` size does not predict it (see
  [Cache memory](#cache-memory)).
- An entry evicted between lookup and use fails the scan with `layer cache
  missing`; the adapter retries it as a `cache` failure. Frequent `cache`
  failures mean the budget is too small.
- `trivy.cacheMaxSize` is deprecated and ignored.

To measure on your workload, point a test cache at a representative image mix
and run cold and warm scans with the pod counts you plan. Record `INFO memory`
(`used_memory`, `used_memory_dataset`, `used_memory_rss`) and `evicted_keys`
before and after, sample `fanal::*` keys with `SCAN` and `MEMORY USAGE`, and
observe at least one full TTL cycle and a scan-all peak. Replicas of the cache
each hold a full copy.

### Network policy

With `networkPolicy.egressEnabled: true`, allow egress to the job store, the
analysis cache, the registries and the database mirrors, plus DNS. Enabling the
Valkey subchart does not add an egress rule; add its pods and port to
`networkPolicy.egress` yourself.

### Termination

The chart's pre-stop hook keeps the API serving for ten seconds while the pod
leaves the Service endpoints, so Harbor's report polls do not hit a closed
listener. A custom `lifecycle.preStop` replaces it and must drain equally long.
`terminationGracePeriodSeconds` (default 60) bounds the rest of shutdown; the
running scan is cancelled and recovered by another pod.

## Upgrade and rollback

Releases before Redis Streams used Pub/Sub. The two protocols cannot run side by
side, so a normal rolling upgrade is unsafe.

1. In Harbor, stop scheduled and bulk scans and scan-on-push, and let
   outstanding work drain. Stop if you cannot confirm that no adapter jobs are
   queued or running.
2. Check that the job store is Redis 6.2+ or Valkey with persistence and
   capacity. Keep the existing job and store namespaces and report retention.
3. Scale the old adapter to zero, upgrade image and chart together, configure
   the analysis cache, and start the new pods. With GitOps, stage the
   scale-to-zero as its own change.
4. Check startup logs and readiness, run one scan and fetch its report, then
   resume submissions.

Old Pub/Sub notifications are not replayed: resubmit stranded work from Harbor.
Existing `fanal.db` contents are not imported; the Redis cache warms up through scans.

Rollback is the same sequence in reverse: stop submissions, drain, confirm the
stream is empty, stop all new pods, then start the old version with the `fs`
cache and one worker per pod. Keep completed reports until Harbor has fetched
them, and never run old workers while Streams jobs are outstanding.

## Background

### Delivery and recovery

The adapter saves each job and its stream delivery atomically before returning
`202`. All pods share one consumer group. A worker holds a one-minute lease on
its delivery and renews it every 20 seconds; every status, report and
acknowledgement write checks the lease first, so a worker that lost ownership
cannot overwrite newer results.

If a pod dies or shuts down mid-scan, the delivery stays pending. After the
lease expires, another pod claims it, checks whether it already completed, and
otherwise scans again. Delivery is therefore at least once: a crash between
scanning and saving can repeat a scan, and a network partition can briefly let
two pods compute the same result, but only one result is kept.

A job fails for good after three started attempts, with a visible retry-limit
error; Harbor can resubmit it once the cause is fixed. Cache and network errors,
timeouts, cancellations and unclassified Trivy failures are retried; so are
registry and manifest fetch errors unless authentication was rejected.
Authentication failures, invalid references, unscannable images and unparsable
reports fail immediately. Storage errors before an attempt starts do not count
against the three.

Acknowledgement removes the stream entry and starts the report retention
(`store.redisScanJobTTL`); time in the queue or in a scan does not consume it.

### Quarantine

Deliveries a worker cannot execute (an undecodable payload, or a job the store
no longer has) move to the `<stream>:quarantine` hash, keyed by delivery ID,
with a `reason` and the original fields. They never expire. The fields can hold
registry credentials, so treat them as secrets. After fixing the cause and
resubmitting from Harbor, delete the entry.

### Cache memory

Cache memory cannot be derived from `fanal.db` size: BoltDB files include free
pages, Redis adds per-key and allocator overhead, and TTL and eviction change
what is retained. The number of unique layers scanned within the TTL drives it,
not the registry size. Pods that miss the same new layer at the same time each
analyze it, since Trivy writes cache entries without a lock; the last write wins.

### Benchmark

One laptop run (macOS ARM64, Trivy 0.74.0) with a small fixed image and a
preloaded vulnerability database:

| Backend | Cold scan | 2 warm pods | 4 warm pods | Cache peak memory |
| --- | --- | --- | --- | --- |
| Redis 7.4 | 527 ms | ~1,124 scans/min | ~2,038 scans/min | 1.3 MB |
| Valkey 8.1 | 181 ms | ~1,096 scans/min | ~1,931 scans/min | 1.2 MB |

Warm pods downloaded no image layers again and returned the same findings as a
cold scan, and going from 2 to 4 pods raised throughput about 1.8 times. Use it to compare
backends and pod counts, not to predict real throughput: in production, Harbor's
jobservice sets the limit first (see [What limits throughput](#what-limits-throughput)).
