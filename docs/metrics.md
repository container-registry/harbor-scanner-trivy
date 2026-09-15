# Operational metrics

The adapter exposes Prometheus metrics on the existing API listener at `/metrics`.
`SCANNER_API_SERVER_METRICS_ENABLED=false` disables `/metrics` (scrapes return
404), application recording and background collection. Scrapes use the API
listener's TLS, client-certificate and network-policy settings.

These metrics cover the adapter instrumentation in [#97](https://github.com/container-registry/harbor-scanner-trivy/issues/97).
Use Harbor to inspect vulnerability findings. Engine cache hits, cache lock waits,
internal phase timings, download/retry instrumentation and cache maintenance
policies remain outside this instrumentation.

## Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `SCANNER_METRICS_COLLECTION_INTERVAL` | `1m` | Background sampling interval, plus up to 10% jitter; at least 1s. |
| `SCANNER_METRICS_COLLECTION_TIMEOUT` | `5s` | Version command deadline and cache-walk time budget; positive and no greater than the interval. Filesystem calls remain subject to OS/filesystem behavior. |
| `SCANNER_METRICS_CACHE_SIZE_ENABLED` | `false` | Opt in to walking the verified local cache directories for logical file sizes. Basic capacity and DB metadata collection do not require this. |
| `SCANNER_METRICS_CACHE_MAX_FILES` | `10000` | Maximum entries visited per cache sample, shared across directories; range 1–1000000. |

A background loop reads cached files and filesystem statistics. Scrapes return
the collected values without starting filesystem work. The engine is sampled on every
tick with a bounded `trivy version --format json` command, because an image upgrade
replaces the binary and both databases change schema under a running pod. The engine
reports only the schema of the database on disk, never the schema its binary was built
against. A failed probe removes `db_schema_version` and sets `metadata_collection_success` to 0, while
`build_info` keeps the last known version: the binary has not changed. The adapter
metadata API reuses that probe while it is younger than the collection interval, so
Harbor's polling does not start a Trivy process per request. File walks do not
follow symlinks. Missing or unsupported cache layouts produce collection failures and omit
the affected size series. They do not report a zero size. Capacity areas and replicas may
refer to the same filesystem: do not sum them as independent disks.

Metadata collection checks for a regular database file and parseable metadata.
It cannot establish database integrity because it does not open the database. Missing DBs are valid
`db_present=0` observations; unreadable/malformed metadata is unknown. Java DBs
can be absent until needed. `db_updates_enabled` follows the skip-update flags;
Trivy's `offline-scan` flag alone does not disable database downloads. The adapter
metadata API also includes Java DB updated-at, including with updates disabled.

## Metric families

Every metric below uses the prefix `harbor_scanner_trivy_`. Histograms export
`_bucket`, `_sum`, and `_count`. Times are seconds and sizes are bytes.

| Suffix | Type | Application labels | Meaning |
|---|---|---|---|
| `build_info` | gauge | adapter_version, trivy_version | Adapter and Trivy binary versions. |
| `http_requests_total` | counter | route, method, code | API requests by route template. |
| `http_request_duration_seconds` | histogram | route, method | API handler duration. |
| `jobs_enqueued_total` | counter | capability, format | Durably enqueued tasks. |
| `job_dispatch_total` | counter | result | Worker dispatch outcomes, including skipped locks. |
| `publish_no_subscribers_total` | counter | — | Deprecated: Streams do not require online subscribers. |
| `scan_retries_total` | counter | — | Attempts after interrupted execution or cache failure. |
| `lease_losses_total` | counter | — | Failed lease renewal or lost ownership. |
| `queue_unacknowledged_jobs` | gauge | — | Shared stream length including pending jobs; use max across pods. |
| `queue_quarantined_jobs` | gauge | — | Malformed deliveries retained outside the active queue for inspection; use max across pods. Any nonzero value needs investigation. |
| `queue_collection_success` | gauge | — | Whether the latest queue collection succeeded. Failed measurements are removed. |
| `queue_collection_last_success_timestamp_seconds` | gauge | — | Last successful queue collection; use `time() - metric` for its age. |
| `queue_collection_errors_total` | counter | query | Failed queue measurements by query (`quarantine`, `length`, `oldest`, `group`). Counts measurement failures, not scan failures. Each sample can fail every query, so this is roughly four times the number of failed samples during an outage. |
| `queue_group_recreated_total` | counter | — | Consumer group recreations after the queue backend lost it. Until each one, no delivery could be read at all, so any increase is worth an alert even though the adapter recovers on its own. |
| `queue_oldest_age_seconds` | gauge | — | Age of oldest unacknowledged delivery, sampled every ten seconds. |
| `job_attempts_total` | counter | capability, format, outcome | Observed attempts, including retryable failures; not unique artifacts or terminal jobs. |
| `job_failures_total` | counter | stage, category | Primary failures of controller executions. |
| `job_duration_seconds` | histogram | capability, outcome | Controller processing and persistence duration after lock acquisition. |
| `queue_wait_duration_seconds` | histogram | capability | Adapter enqueue-to-lock-acquisition duration, excluding Harbor's queue. |
| `jobs_in_progress` | gauge | — | Locally executing jobs. |
| `worker_concurrency` | gauge | — | Configured local worker capacity. |
| `ready` | gauge | check | Result of each readiness check (`queue`, `worker`, `binary`), recorded when the probe runs. A check this process does not own has no series: an API built without a worker reports neither `queue` nor `worker`. |
| `last_scan_success_timestamp_seconds` | gauge | — | Last successfully persisted completion; absent until observed. |
| `scan_timeout_seconds` | gauge | — | Configured Trivy CLI timeout, not the entire job budget. |
| `subprocess_duration_seconds` | histogram | command, outcome | Trivy child process duration. |
| `subprocess_exits_total` | counter | command, reason | Trivy child termination reason: `success`, `nonzero_exit`, `timeout`, `signal`, `start_error`. Timeouts are reported separately, so `signal` means an external kill such as an OOM. |
| `subprocess_exit_code_total` | counter | command, code | Trivy child exit status (`0`, `1`, `2`, `137`, `143`, `other`). Absent when the child never started, so it does not count `start_error` terminations. A child killed by a signal has no exit status and counts as `other`. |
| `subprocess_max_rss_bytes` | histogram | command | Completed child peak RSS, not container peak or live usage. |
| `sbom_accessory_events_total` | counter | event | SBOM accessory lookup and fallback events (multiple per job). |
| `report_size_bytes` | histogram | capability, format, encoding | Matched raw and compressed report sizes on applied writes. |
| `store_bytes_written_total` | counter | record, encoding | Applied payload bytes; raw is uncompressed equivalent, not resident memory. |
| `store_operations_total` | counter | operation, outcome | Logical adapter store operations and outcomes: enqueue, read, status, report and acknowledge. |
| `store_operation_duration_seconds` | histogram | operation | Logical adapter store operation duration including failures. |
| `report_fetch_total` | counter | result | Report poll outcomes; not_found does not prove expiry. |
| `report_fetch_age_seconds` | histogram | capability, format | Age of successfully fetched report since recorded completion, not remaining TTL. |
| `scan_job_ttl_seconds` | gauge | — | Effective retention TTL; zero disables expiry in the store. |
| `db_present` | gauge | database | Local database file and metadata presence (not read integrity). |
| `db_updated_timestamp_seconds` | gauge | database | Database content build timestamp. |
| `db_next_update_timestamp_seconds` | gauge | database | Advertised database next update timestamp. |
| `db_downloaded_timestamp_seconds` | gauge | database | Recorded local download timestamp, not download attempts. |
| `db_updates_enabled` | gauge | database | Effective automatic database update policy. |
| `db_schema_version` | gauge | database | Schema version of the local database file, as the engine reports it. Absent until that database has been downloaded, and absent when the engine could not be probed; use `db_present` to tell the two apart. The engine does not report the schema version it supports, so a mismatch shows up as a `db_schema` scan failure, not as a comparison here. |
| `analysis_cache_backend_info` | gauge | backend | Configured analysis-cache backend: `filesystem`, `redis`, `memory`, or `unknown`. Value is 1; no server URL or credentials are exposed. |
| `metadata_collection_success` | gauge | — | Whether Trivy version and local vulnerability/Java metadata checks succeeded, including valid database absence. Does not test database integrity. |
| `metadata_last_success_timestamp_seconds` | gauge | — | Last successful monitoring refresh of vulnerability/Java metadata; not database build or download time. |
| `cache_size_bytes` | gauge | kind | Logical regular-file bytes for the verified local cache layout. `kind="analysis"` is emitted only for the filesystem backend; DB and Java sizes remain local for every backend. `kind="tmp_trivy"` is not cache: it is what running and abandoned children hold under the temp directory. |
| `storage_capacity_bytes` | gauge | area | Filesystem capacity at the configured path; areas may share a filesystem. |
| `storage_available_bytes` | gauge | area | Filesystem bytes available to the scanner at the configured path. |
| `storage_inodes_available` | gauge | area | Available filesystem inodes where supported. |
| `storage_collection_success` | gauge | collector | Whether the latest storage collector run succeeded. |
| `storage_collection_duration_seconds` | histogram | collector | Background storage collection duration. |
| `storage_last_success_timestamp_seconds` | gauge | collector | Last successful storage collection. |
| `temp_dirs_reaped_total` | counter | — | Abandoned Trivy temp directories removed. Each one is a child that died without cleaning up, so a rising rate means scans are being killed. |
| `temp_dirs_present` | gauge | — | Trivy temp directories left in place at the last sweep, including those of running scans. Sampled every ten minutes, not on scrape. |
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
semantics. Each client is registered once. These collectors read client statistics without scanning Redis keys or calling
server `INFO`. Use a Redis/Valkey exporter for server memory and evictions; those
measurements cover every workload sharing the instance.

## Counting and interpreting results

- A request can enqueue multiple tasks by capability/format. Redis Streams retain
  deliveries until acknowledged, and workers use renewable leases.
  `job_dispatch_total{result="lock_busy"}` counts ownership contention. It does
  not count a scan failure. Delivery is at least once: ownership checks block
  stale result writes, but an interrupted scan can execute again.
- `queue_wait_duration_seconds` measures adapter enqueue to first-attempt lock acquisition.
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
- Failures are classified from Trivy's fatal report, the last `FATAL` line and
  what follows it, not from the whole stderr buffer. A run logs a failed
  database mirror before succeeding from the next one, so the buffer of a scan
  that ended on a registry 401 also contains download errors. Output with no
  fatal line, from a child that was killed, is classified whole.
- `category="rate_limit"` and `category="db_download"` are retryable infrastructure
  failures: a throttling registry, or a vulnerability/Java database that could not be
  fetched. `category="db_schema"` (binary and database schema disagree) and
  `category="unsupported_artifact"` (the reference is not a scannable image) are
  terminal, so the worker does not retry them. A schema or flag complaint is
  classified before the download rules, and so is a `cache` fault: Trivy reaches
  its bolt analysis cache through the same `DB error:` wrapper as a database
  download, and the two need different responses from an operator.
- Report-size raw/compressed observations describe the same applied report write.
  Calculate a byte-weighted compression ratio from the sums. Dividing unrelated
  percentiles does not give that ratio.
  Byte-write counters include only confirmed applied writes. Duplicate `SETNX`
  calls can return successfully with `outcome="not_applied"`; they add no bytes.
- A missing report may be expired or an unknown ID. `report_fetch_age_seconds`
  measures successful retrieval age since stored completion, not TTL remaining.
  Old jobs without that timestamp are excluded. Retention refreshes on writes;
  bytes-written-rate × TTL is not actual Redis resident memory. `GetConfig`
  derives a positive effective TTL from scan timeout when its setting is zero;
  direct store callers can still use zero to disable expiry.
- `/probe/ready` fails only for what stops this pod from serving: the job
  backend answering and still holding the worker's consumer group (`queue`), the
  read loop having iterated or renewed a lease within three lease periods
  (`worker`), and the Trivy binary being on `PATH` (`binary`, cached for a
  minute). Database freshness, disk space and the analysis cache are deliberately
  not readiness. A 503 removes the pod from the Service, Harbor's metadata ping
  then fails, its `Metadata` goes nil, and a scan-all in that state finishes as
  Success having scanned nothing; a stale database still produces reports. Alert
  on `db_next_update_timestamp_seconds` and `storage_available_bytes` instead.
  `/probe/healthy` stays unconditional, so a failing readiness check never
  restarts the pod.
- `area="tmp"` covers `os.TempDir()`, where Trivy extracts layers. It is often
  a different filesystem from the cache and fills up on its own.
  `SCANNER_TRIVY_MAX_IMAGE_SIZE` adds to it rather than bounding it: reaching
  the uncompressed size means writing every layer there first. Trivy removes
  its `$TMPDIR/trivy-<pid>` directory when it exits, but a child that is
  OOM-killed never does, so the adapter sweeps directories whose pid is no
  longer alive every ten minutes and counts them in `temp_dirs_reaped_total`.
  Reaping runs even with metrics disabled; only the counters go away.
- Child peak RSS is available after termination on Linux (converted from KiB)
  and macOS (already bytes). It is not live usage, a sum of concurrent children,
  or total container peak. If the child never starts or the adapter is killed,
  usage may be unavailable. Check the container termination reason to determine
  whether a signal was caused by OOM.
- Queue collection failures are logged once per state change, not once per
  sample, so a Redis outage produces one error line and one recovery line.
  `rate(queue_collection_errors_total[5m])` is the machine-readable rate, and
  `queue_collection_success` shows the current state.
- `query="group"` checks that the worker consumer group exists. A job backend
  without persistence comes back empty after a restart, and the group created at
  startup is gone: stream length, age and quarantine all keep answering while no
  delivery can be read at all. The worker recreates the group when a read
  reports `NOGROUP` and counts it in `queue_group_recreated_total`, logging one
  line per recreation rather than one per failed read.
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
upstream scheduling context. The stacked chart change provides the dashboard and Helm provisioning.
