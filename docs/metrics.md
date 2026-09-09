# Operational metrics

The adapter exposes Prometheus metrics on the existing API listener at `/metrics`.
`SCANNER_API_SERVER_METRICS_ENABLED=false` disables application recording and
background collection. Scraping uses the API listener's TLS, client-certificate
and network-policy settings; no extra listener is opened.

This implements the adapter instrumentation phase of [#97](https://github.com/container-registry/harbor-scanner-trivy/issues/97).
Vulnerability findings belong in Harbor. Engine cache hits, cache lock waits,
internal phase timings, download/retry instrumentation and cache maintenance
policies are not implemented by this change.

## Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `SCANNER_METRICS_COLLECTION_INTERVAL` | `1m` | Background sampling interval, plus up to 10% jitter; at least 1s. |
| `SCANNER_METRICS_COLLECTION_TIMEOUT` | `5s` | Version command deadline and cache-walk time budget; positive and no greater than the interval. Filesystem calls remain subject to OS/filesystem behavior. |
| `SCANNER_METRICS_CACHE_SIZE_ENABLED` | `false` | Opt in to walking the verified local cache directories for logical file sizes. Basic capacity and DB metadata collection do not require this. |
| `SCANNER_METRICS_CACHE_MAX_FILES` | `10000` | Maximum entries visited per cache sample, shared across directories; range 1–1000000. |

Collection reads cached files and filesystem statistics in a background loop,
never on the scrape path. The engine version is obtained with a bounded
`trivy version --format json` command, retried until available. File walks do not
follow symlinks. Missing or unsupported cache layouts produce collection failure
and absent size series, not invented zeros. Capacity areas and replicas may
refer to the same filesystem: do not sum them as independent disks.

Metadata collection verifies that a regular database file and parseable metadata
exist. It does not open or validate the database contents. Missing DBs are valid
`db_present=0` observations; unreadable/malformed metadata is unknown. Java DBs
can be absent until needed. `db_updates_enabled` follows the skip-update flags;
Trivy's `offline-scan` flag alone does not disable database downloads. The adapter
metadata API also includes Java DB updated-at, including with updates disabled.

## Metric families

Every suffix below has prefix **`harbor_scanner_trivy_`**. Histograms export
`_bucket`, `_sum`, and `_count`. Times are seconds and sizes are bytes.

| Suffix | Type | Application labels | Meaning |
|---|---|---|---|
| `build_info` | gauge | adapter_version, trivy_version | Adapter and Trivy binary versions. |
| `http_requests_total` | counter | route, method, code | API requests by route template. |
| `http_request_duration_seconds` | histogram | route, method | API handler duration. |
| `jobs_enqueued_total` | counter | capability, format | Successfully published tasks (including zero-subscriber publications). |
| `job_dispatch_total` | counter | result | Worker dispatch outcomes, including skipped locks. |
| `publish_no_subscribers_total` | counter | — | Publications reaching no subscribers. |
| `job_attempts_total` | counter | capability, format, outcome | Terminal observed executions, not unique artifacts. |
| `job_failures_total` | counter | stage, category | Primary failures of controller executions. |
| `job_duration_seconds` | histogram | capability, outcome | Controller processing and persistence duration after lock acquisition. |
| `queue_wait_duration_seconds` | histogram | capability | Adapter enqueue-to-lock-acquisition duration, excluding Harbor's queue. |
| `jobs_in_progress` | gauge | — | Locally executing jobs. |
| `worker_concurrency` | gauge | — | Configured local worker capacity. |
| `last_scan_success_timestamp_seconds` | gauge | — | Last successfully persisted completion; absent until observed. |
| `scan_timeout_seconds` | gauge | — | Configured Trivy CLI timeout, not the entire job budget. |
| `subprocess_duration_seconds` | histogram | command, outcome | Trivy child process duration. |
| `subprocess_exits_total` | counter | command, reason | Trivy child termination reason; signal does not imply OOM. |
| `subprocess_max_rss_bytes` | histogram | command | Completed child peak RSS, not container peak or live usage. |
| `sbom_accessory_events_total` | counter | event | SBOM accessory lookup and fallback events (multiple per job). |
| `report_size_bytes` | histogram | capability, format, encoding | Matched raw and compressed report sizes on applied writes. |
| `store_bytes_written_total` | counter | record, encoding | Applied payload bytes; raw is uncompressed equivalent, not resident memory. |
| `store_operations_total` | counter | operation, outcome | Logical adapter store operations and outcomes. |
| `store_operation_duration_seconds` | histogram | operation | Logical adapter store operation duration including failures. |
| `report_fetch_total` | counter | result | Report poll outcomes; not_found does not prove expiry. |
| `report_fetch_age_seconds` | histogram | capability, format | Age of successfully fetched report since recorded completion, not remaining TTL. |
| `scan_job_ttl_seconds` | gauge | — | Effective retention TTL; zero disables expiry in the store. |
| `db_present` | gauge | database | Local database file and metadata presence (not read integrity). |
| `db_updated_timestamp_seconds` | gauge | database | Database content build timestamp. |
| `db_next_update_timestamp_seconds` | gauge | database | Advertised database next update timestamp. |
| `db_downloaded_timestamp_seconds` | gauge | database | Recorded local download timestamp, not download attempts. |
| `db_updates_enabled` | gauge | database | Effective automatic database update policy. |
| `metadata_collection_success` | gauge | — | Whether the last metadata refresh succeeded. |
| `metadata_last_success_timestamp_seconds` | gauge | — | Last successful metadata refresh. |
| `cache_size_bytes` | gauge | kind | Logical regular-file bytes for the verified local cache layout. |
| `storage_capacity_bytes` | gauge | area | Filesystem capacity at the configured path; areas may share a filesystem. |
| `storage_available_bytes` | gauge | area | Filesystem bytes available to the scanner at the configured path. |
| `storage_inodes_available` | gauge | area | Available filesystem inodes where supported. |
| `storage_collection_success` | gauge | collector | Whether the latest storage collector run succeeded. |
| `storage_collection_duration_seconds` | histogram | collector | Background storage collection duration. |
| `storage_last_success_timestamp_seconds` | gauge | collector | Last successful storage collection. |
| `oldest_running_job_age_seconds` | gauge | — | Oldest local execution age; zero while idle. |
| `redis_pool_connections` | gauge | state (`total`, `idle`) | In-memory client pool statistics; total includes idle. |
| `redis_pool_size` | gauge | — | Effective base pool size, not the hard limit. |
| `redis_pool_max_active_connections` | gauge | — | Effective hard connection limit; zero means unlimited. |
| `redis_pool_requests_total` | counter | result (`hit`, `miss`) | Connection reuse, not analysis-cache reuse. |
| `redis_pool_timeouts_total` | counter | — | Connection wait timeouts. |
| `redis_pool_waits_total` | counter | — | Connection waits. |
| `redis_pool_wait_duration_seconds_total` | counter | — | Accumulated connection waiting time. |
| `redis_pool_stale_connections_total` | counter | — | Stale connections removed from the pool. |

The client's cumulative pool counters reset on client replacement and the
upstream 32-bit counters can wrap; apply Prometheus `rate`/`increase` reset
semantics. Each client is registered once. No Redis keyspace scans or server
`INFO` calls are made by these collectors. Actual server memory and evictions
come from a Redis/Valkey exporter, with shared-instance scope documented.

## Counting and interpreting results

- A request can publish multiple tasks by capability/format. Pub/Sub broadcasts
  to replicas; `job_dispatch_total{result="lock_busy"}` counts skipped copies,
  not failed scans. An accepted publication can have zero subscribers. There is
  no durable queue-depth metric and no exactly-once guarantee: the existing
  fixed lock lifetime can be exceeded by long executions.
- `queue_wait_duration_seconds` measures adapter enqueue to lock acquisition.
  Harbor's own queue is upstream. Old messages without an enqueue timestamp and
  future timestamps are excluded. Controller duration includes target resolution,
  fallback, report transformation and persistence. Subprocess duration measures
  each child invocation separately.
- `job_attempts_total` increments on the original controller outcome. Successful
  persistence of a failed status does not turn a failed scan into a success.
  A recovered SBOM fallback is a successful job with a failed subprocess attempt.
  Report polls never increment job execution counters.
- `job_failures_total` records one primary error, with preserved typed categories
  where possible. Store errors can additionally reflect a failed status write.
  Child stderr classification remains heuristic; exact diagnostic detail stays
  in logs. Error labels never contain raw stderr or image identifiers.
- Report-size raw/compressed observations describe the same applied report write.
  Compare sums for a byte-weighted compression ratio, not unrelated percentiles.
  Byte-write counters include only confirmed applied writes. Duplicate `SETNX`
  calls can return successfully with `outcome="not_applied"`; they add no bytes.
- A missing report may be expired or an unknown ID. `report_fetch_age_seconds`
  measures successful retrieval age since stored completion, not TTL remaining.
  Old jobs without that timestamp are excluded. Retention refreshes on writes;
  bytes-written-rate × TTL is not actual Redis resident memory. `GetConfig`
  derives a positive effective TTL from scan timeout when its setting is zero;
  direct store callers can still use zero to disable expiry.
- Child peak RSS is available after termination on Linux (converted from KiB)
  and macOS (already bytes). It is not live usage, a sum of concurrent children,
  or total container peak. If the child never starts or the adapter is killed,
  usage may be unavailable. A signal alone does not establish OOM.
- Last-success and metadata timestamps remain absent until observed. An idle
  installation need not have a recent successful scan. Use collection-success
  and last-success timestamps together; failed samples remove invalid snapshot
  values and preserve the last successful collection time.

Labels are bounded centrally: unknown capability/format/method/error values map
to `other`. HTTP route templates are used and unmatched paths share one series;
probes and `/metrics` are excluded from API workload charts. There are no image,
project, repository, digest, scan-ID, CVE, credential or raw-path labels. Binary
versions are the only build-info labels. Core execution/fetch/dispatch/store
counters are initialized for idle dashboards; latency histograms have no samples
until work occurs.

Aggregate counter rates across replicas before ratios; aggregate histogram
buckets before quantiles. Execution buckets cover 0.1s through 24h. Redis, HTTP
and sampling durations use the Prometheus default short-duration buckets. Show
failed and successful latency separately. Keep per-replica DB timestamps visible
and use the oldest relevant timestamp to find stale replicas; missing series need
a separate presence check.

## Sources for a dashboard

Scrape identity should include stable `cluster`, `namespace`, `scanner` and a
replica label (`pod` on Kubernetes). Standalone scrape configurations can attach
static deployment labels:

```yaml
scrape_configs:
  - job_name: harbor-trivy
    static_configs:
      - targets: ["scanner.example:8080"]
        labels:
          cluster: production
          namespace: harbor
          scanner: trivy
```

Use the scanner's metrics for execution/worker health, database freshness,
cache/storage and report persistence. Use container/node metrics for CPU, memory,
limits, throttling and OOM/restarts. Adapter Go/process collectors are retained
and describe only the adapter process. Harbor jobservice metrics can provide
upstream scheduling context. A dedicated dashboard and Helm provisioning are
provided in the stacked chart change, not this metrics commit.
