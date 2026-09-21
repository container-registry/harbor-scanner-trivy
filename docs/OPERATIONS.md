# Operating the scanner

What to watch, what each signal means, and what to do when it moves. Metric
names omit the `harbor_scanner_trivy_` prefix. Everything here was checked
against the adapter, Harbor and Trivy sources; file references point at the
code that produces the behaviour, not at documentation.

## Signals at a glance

| Question | Signal | Healthy | Alert |
|---|---|---|---|
| Is the adapter scraped at all? | `up{scanner!=""}` | 1 per pod | Scanner down; Scanner metrics absent |
| Can the pod serve? | `GET /probe/ready`, `ready{check}` | 200, all checks 1 | Scanner down (pods leave the Service) |
| Is the job queue reachable and consumed? | `queue_collection_success`, `queue_collection_errors_total{query}`, `queue_group_recreated_total` | 1, flat, flat | Queue collection failing |
| Is work piling up unread? | `queue_oldest_age_seconds` with `jobs_in_progress` | oldest age 0 when idle | Deliveries stuck in queue while workers idle |
| Are scans succeeding? | `job_attempts_total{outcome}`, `job_failures_total{stage,category}` | successes > 0 while attempts > 0 | Scans attempted but none succeeded in 24h; Failure category spike |
| Did Trivy die or time out? | `subprocess_exits_total{reason}`, `subprocess_exit_code_total{code}`, both with `command=~"image\|sbom"` to leave out the `version` probe | `reason="success"`, `code="0"` | Failure category spike |
| Is the vulnerability DB current? | `db_present`, `db_next_update_timestamp_seconds`, `db_updated_timestamp_seconds`, `db_schema_version` | present, next update in the future, schema matches the engine | Vulnerability DB not refreshed although scans run |
| Does Harbor see the scanner? | `http_request_duration_seconds{route="/api/v1/metadata"}` p95 | well under 4 s | Metadata endpoint slow |
| Is the disk filling? | `storage_available_bytes{area}`, `cache_size_bytes{kind}`, `temp_dirs_present` | stable | Local disk row on the dashboard |

The dashboard `harbor-trivy-scanner` (chart `deploy/chart/dashboards/trivy.json`) has a row per line of this table.

## Readiness semantics

`/probe/ready` returns 503 only when the pod genuinely cannot serve: the job Redis is unreachable or the consumer group is missing, the worker loop has not run within three lease periods, or the `trivy` binary is not on the path. The worker's heartbeat is written on an answered read and on each lease renewal, so a scan that outlasts three lease periods keeps the pod ready while a loop that stopped does not. It deliberately ignores database presence, disk space and the analysis cache. A pod that leaves the Service makes Harbor's `/api/v1/metadata` ping fail, Harbor then records no capabilities for the scanner, rejects scans as "does not support scanning artifact with mime type", and a scan-all started in that state finishes as Success with zero scans (`src/controller/scan/base_controller.go:539` in Harbor). Readiness is therefore narrow on purpose; the wider conditions are gauges and alerts.

`/probe/healthy` answers 200 unconditionally. Harbor's own health checker reads it with a 60 s timeout every 10 s and publishes it as `harbor_up{component="trivy"}`, so that metric only proves the HTTP listener answers.

## Failure categories and what to do

`job_failures_total{category}` for a Trivy subprocess failure is derived from the FATAL line of its stderr (`pkg/trivy/wrapper.go`, `classifyTrivyError`); failures the adapter raises itself around the scan - registry access, report parsing, storage and persistence - carry their own category instead. Retryable categories are retried within the worker's attempt limit; terminal ones fail the scan immediately.

| Category | Meaning | Retried | Action |
|---|---|---|---|
| `rate_limit` | TOOMANYREQUESTS / 429 from a registry or DB mirror | yes | Point `SCANNER_TRIVY_DB_REPOSITORY` and `SCANNER_TRIVY_JAVA_DB_REPOSITORY` at a mirror list you control. The chart sets them to `ghcr.io/aquasecurity/trivy-db` and `ghcr.io/aquasecurity/trivy-java-db`, so Trivy's own `mirror.gcr.io` fallback is not in play unless you add it; putting a mirror first is an override you make, not a default you keep. A 429 whose body is not a registry error (proxy, WAF) is not retried by Trivy and skips the mirror list. |
| `db_download` | DB or Java DB could not be downloaded or extracted | yes | Check egress to the mirrors; check `storage_available_bytes{area="cache"}`: an extraction failure has already deleted the previous DB (`pkg/downloader/download.go:58`), so the next scan needs a full download. |
| `db_schema` | Local DB schema does not match the engine, or `--skip-db-update` was combined with an old schema | no | A rolled-back image against a shared cache, or an air-gapped upgrade across a schema boundary. Refresh the side-loaded DB or clear `db/` on the volume. |
| `unsupported_artifact` | The artifact is not an image (Helm chart, SBOM, signature) | no | Nothing to fix on the scanner; Harbor should not have dispatched it. |
| `auth` | Registry returned 401/403 | no | The per-scan robot is deleted when the task ends; reproduce with a fresh robot. If Harbor's own token service failed, `job.go:203` in Harbor logs it but still sends an empty Authorization header. |
| `network` | connection refused, no such host, dial tcp | yes | Registry or mirror reachability. |
| `timeout` | context deadline exceeded | yes | See "Timeouts". |
| `cache` | Redis cache error, layer cache missing, cache may be in use | yes | See "Cache backends". |
| `unscannable_layer` | archive extraction failed, unexpected EOF | no | Corrupt or non-image layer. |
| `trivy_execution` | Any other non-zero exit | yes | Read the stderr tail in the adapter log (`ScanError.Detail` carries the last 4 KiB). |
| `storage_full`, `storage_io` | ENOSPC / EIO from the adapter's own file operations | yes | Disk. A full disk inside the Trivy child shows up as `trivy_execution` with "no space left on device" in the detail. |

`subprocess_exits_total{reason}`: `timeout` is the adapter's own deadline, `canceled` its own cancellation (shutdown or a lost lease), `signal` a kill from outside the adapter (OOMKill, an operator's SIGTERM), `nonzero_exit` is a status the child returned itself (Trivy's 1, the runtime's 2), `start_error` means the binary could not start, and `other` is a child that exited 0 while the run still failed, which points at the adapter rather than at Trivy. A child that reached its own exit status keeps `nonzero_exit` even if the context expired meanwhile.

`subprocess_exit_code_total{code}` keeps the numeric status, reporting a killed child as 128+signal like a shell does: Trivy itself exits 0 or 1, the Go runtime 2 (a rejected `GOMEMLIMIT` never reaches `main`), 137 is SIGKILL and 143 SIGTERM. The adapter also kills the child when its own deadline expires, so 137 does not identify an OOM on its own; read it together with `reason` and the container's termination reason.

## Vulnerability DB and Java DB lifecycle

- Trivy refreshes the vulnerability DB at scan start once `NextUpdate` has passed, with a one hour re-download damper (`pkg/db/db.go`, `isNewDB`). `NextUpdate` comes from the published `metadata.json`; measured cadence is 24 h. Nothing refreshes it between scans: an idle scanner sits past `NextUpdate` legitimately.
- The Java DB is refreshed only while scanning an image that contains JAR files, once per process, inside the scan's timeout budget (`pkg/fanal/analyzer/language/java/jar/jar.go`). Its `NextUpdate` is three days out. A registry with few Java images shows an old Java index for weeks; that is not a fault.
- Standalone Trivy has no stale-DB fallback: a failed refresh is exit 1 for that scan. Server mode does fall back; the adapter runs standalone.
- `--skip-db-update` (`SCANNER_TRIVY_SKIP_UPDATE`) with a valid DB of any age is silent at INFO level. Side-loaded DBs need `DownloadedAt` set in `metadata.json` (use `trivy --download-db-only` or `oras` per Trivy's air-gap docs), otherwise Trivy re-downloads them with a warning.
- `db_schema_version{database}` is the schema of the file on disk as reported by `trivy version --format json`. The engine does not report the schema it supports; a mismatch surfaces as the `db_schema` failure category.
- Warm-up for a fresh volume: run `trivy image --download-db-only` and `--download-java-db-only` in an init step, or accept that the first scan (and the first Java scan) pays the download inside its timeout.

## Cache backends

- Filesystem (`fs`): bbolt `fanal/fanal.db` on the pod's volume. One process at a time; a second opener gets "cache may be in use by another process" after 5 s. Corruption is not repaired automatically (the vulnerability DB does self-heal, the analysis cache does not): delete `fanal/` or run `trivy clean --scan-cache`. The file grows with every distinct layer seen; `cache_size_bytes{kind="analysis"}` tracks it when size collection is enabled.
- Redis (`redis://` in `SCANNER_TRIVY_CACHE_BACKEND`): reads that fail are treated as cache misses, so an unreachable Redis looks like a cold cache (full CPU cost) until the first write fails the scan. There is no degraded mode. Watch the Valkey exporter (`redis_up`, evictions, memory) on the dashboard's analysis cache row; the adapter cannot see this connection.
- `layer cache missing: sha256:…` means a blob disappeared between lookup and use: `SCANNER_TRIVY_CACHE_TTL` shorter than a scan, or `maxmemory` eviction. Keep the TTL well above the scan timeout and size `maxmemory` for the working set.
- The cache key includes every analyzer version and the skip-files/skip-dirs lists. Each Trivy release that changes an analyzer invalidates the whole cache; expect a re-analysis storm after upgrades.

## Queue recovery

The queue is a Redis Stream with a consumer group (`<namespace>:stream:v1:scan_artifact`, group `scanner`). Deliveries are acknowledged and deleted once the job reaches a terminal status, with a successful scan's report stored first; a terminally failed scan is acknowledged too, with no report. Unacknowledged ones are reclaimed by any worker after the one minute lease.

- `queue_collection_success` = 0 with `queue_collection_errors_total{query="group"}` rising on its own, the other `query` labels flat: the consumer group is gone. (All four labels rising together is the job Redis being unreachable, not a lost group.) The stream and its deliveries may well survive, so this is lost group state rather than lost data: check the job Redis for a restart without persistence, and for a manual `XGROUP DESTROY`. The worker recreates the group and counts `queue_group_recreated_total`; on older builds restart the StatefulSet.
- `queue_oldest_age_seconds` climbing while `jobs_in_progress` is 0 on every replica: entries are not being read. Check the group as above, then the worker logs for `Recovering scan delivery`.
- `queue_quarantined_jobs` > 0: a delivery could not be decoded. Inspect `<namespace>:stream:v1:scan_artifact:quarantine` with `redis-cli` (payloads contain registry credentials, treat as secrets), fix the producer, delete the entry.
- `scan_retries_total` and `lease_losses_total` rising: workers are being interrupted mid-scan (OOMKill, timeout, restart) or the lease renewal is failing. Correlate with `subprocess_exits_total{reason="signal"}` and container restarts.
- Reports live in the same Redis with a TTL (`SCANNER_STORE_REDIS_SCAN_JOB_TTL`); losing the Redis data loses queued work and unread reports, Harbor marks those scans as errors after its poll times out.

## Memory and GOMEMLIMIT

Trivy sets no Go memory limit; files below 100 MiB are read whole into memory and `--parallel` (default 5) analyses layers and files concurrently. The adapter sets `GOMEMLIMIT` for the child to 80% of the cgroup limit by default (`SCANNER_TRIVY_CHILD_GOMEMLIMIT`, `off` to disable), which turns most OOMKills into slower garbage-collected scans. `subprocess_max_rss_bytes` records each child's peak. Secret scanning is the expensive scanner; `SCANNER_TRIVY_SECURITY_CHECKS=vuln` disables it. `SCANNER_TRIVY_MAX_IMAGE_SIZE` refuses oversized images: the compressed size is checked from the manifest before anything is pulled, and the uncompressed size is added up as layers download, failing the scan as soon as the running total exceeds the limit, with up to `--parallel` layers in flight. The layers it does fetch stay in the temp directory for the rest of the scan.

## Timeouts

`SCANNER_TRIVY_TIMEOUT` is passed as Trivy's `--timeout` and used as the adapter's own deadline. Trivy spends that single budget on the DB download, the Java DB download, the image pull and the analysis, so the first scan after a cache wipe and the first Java image are the ones that time out. The adapter reports the deadline as `subprocess_exits_total{reason="timeout"}` and category `timeout`. Harbor stops polling a report after 30 minutes of inactivity and gives every call to the adapter 5 seconds, so keep the adapter timeout below 30 minutes and the metadata endpoint fast.

## Temp and disk

Trivy writes under its own `$TMPDIR/trivy-<random>` (DB downloads, post-analyzer copies, files over 100 MiB, materialised layers with `--max-image-size`). It cleans up on a normal exit or SIGTERM, never after SIGKILL, and the suffix is random rather than a pid, so nothing else can tell a running scan's directory from an abandoned one. The adapter therefore points each child's `TMPDIR` at a directory it made under its own root, `$TMPDIR/harbor-scanner-trivy-<random>/`, and removes it once the child is gone, however it died. Only an adapter process that is itself killed leaves its root behind, on the pod's `emptyDir`, until the container comes back; the new process removes every sibling root at startup (`temp_dirs_reaped_total`), which is safe because one adapter runs per temp filesystem. The root's name is random rather than the pid so that a restarted process does not inherit the dead one's root. A clean shutdown removes the root outright. Two adapters sharing one `/tmp` is not a supported topology: each would remove the other's root at startup. `storage_available_bytes{area="tmp"}` reports the temp filesystem and `cache_size_bytes{kind="tmp_trivy"}` what this adapter's children hold. Point `TMPDIR` at the cache volume if the container's writable layer is small.

## Harbor-side caveats

- Every Harbor call to the adapter has a 5 s client timeout; a slow `/api/v1/metadata` makes the scanner Unhealthy and the outage is reported as a capability error, not as unhealthy.
- Harbor never retries a 404 or 5xx on report polling. An adapter that lost a scan id (Redis restart) fails that scan.
- A failed scan's reason exists only in the jobservice job log (`GET /projects/{p}/repositories/{r}/artifacts/{ref}/scan/{report_id}/log`), swept after one day. The adapter log keeps the classified detail.
- `IMAGE_SCAN_EXECUTION_RETENTION_COUNT` defaults to 1; after the sweep a valid report renders as Error in the UI.
- Harbor has no field for which DB produced a report; use `db_updated_timestamp_seconds` on the scanner side.
- Scan-all and manual scans share one jobservice queue at the same priority with no per-type cap; a scan-all saturates the worker pool for its whole duration.
- Scanner robot accounts never expire on their own; `delete robot account failed` in core logs means a leaked robot.

## Log anchors

Adapter (JSON `msg` field): `Running trivy failed` with `category` and `exit_code`, `Recovering scan delivery` and `Reading scan delivery` (queue reads failing), `Recreated the scan consumer group lost by the queue backend`, `Queue metric collection failed` / `Queue metric collection recovered`, `Scan delivery remains pending for recovery`, `Removed an abandoned Trivy temp directory`.

Trivy (stderr, tab separated `time LEVEL [prefix] message`): `[vulndb] Downloading vulnerability DB...`, `Failed to download artifact`, `Trying to download artifact from other repository...`, `Java DB is cached for 3 days`, `The first run cannot skip downloading DB`, `Trivy version is old`, `--skip-db-update cannot be specified with the old DB schema`, `layer cache missing`, `cache may be in use by another process`, `context deadline exceeded`, `unsupported artifact type`, `[secret] The size of the scanned file is too large`.

Harbor core: `failed to ping scanner`, `delete robot account failed`, `%d vulnerabilities' severity changed`. Jobservice: `Job 'IMAGE_SCAN:…' exit with error`, `Report with mime type … is not ready yet, retry after`, ``Parse `Refresh-After` error``.
