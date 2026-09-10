# Harbor Trivy Scanner and Valkey dashboards

Import [trivy.json](trivy.json) and [valkey.json](valkey.json) into Grafana, or
use a dashboard sidecar to load them from the chart's optional ConfigMap. These
files are the dashboard source; the chart embeds their JSON and leaves Grafana
template expressions unchanged. Provision the dashboards once per Grafana
organization because every scanner release uses the same UIDs.

## Setup

Use an adapter image containing the operational metrics implementation from
[PR #98](https://github.com/container-registry/harbor-scanner-trivy/pull/98).
Older images, including v0.40.1, expose Go/process metrics but cannot populate the
new scanner panels. Backend-aware cache filtering and durable queue panels require
an image containing [PR #106](https://github.com/container-registry/harbor-scanner-trivy/pull/106). Until that implementation is released, explicitly select an
image built from that branch with `image.tag` (or `image.digest`).

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    cluster: production-eu
    # Match your Prometheus serviceMonitorSelector if required:
    # labels:
    #   release: kube-prometheus-stack
  grafanaDashboard:
    enabled: true
    # namespace: monitoring  # if the sidecar only watches this namespace
  collection:
    intervalSeconds: 60
    timeoutSeconds: 5
    cacheSizeEnabled: false
    maxCacheFiles: 10000
```

The ServiceMonitor requires Prometheus Operator. The dashboard ConfigMap defaults
to label `grafana_dashboard: "1"` and annotation `grafana_folder: Harbor`.
Configure the sidecar to watch that label and namespace; enable its folder
annotation support if you want that folder. Labels and annotations are configurable.
Install Grafana and its data sources separately.

## Valkey / Redis dashboard

The linked Valkey / Redis dashboard uses `redis_exporter` metrics from one
cluster, namespace, and exporter Service. It covers memory/maxmemory, key lookups,
evictions and expiry, keys, connections, command activity/errors, network traffic,
uptime, and exporter health. Rates use at least a four-minute window and display
events per minute; network traffic remains bytes per second. Values remain per
server, including when a Service exposes several nodes.

Enable the exporter's metrics and ServiceMonitor (or PodMonitor) in the chart
that owns Redis/Valkey. The official Valkey chart exposes these as `metrics.enabled`
and `metrics.serviceMonitor.enabled`; when used as a `valkey` subchart, prefix
them with `valkey.`. Match Prometheus's monitor labels and preserve the `cluster`,
`namespace`, `service`, and `instance` labels. The exporter is required separately
from the adapter's `/metrics` endpoint. The Valkey dashboard can also be used with
an external Redis server, independently of the adapter image version.

In the Trivy dashboard, Analysis cache (optional) selects the exporter for the
shared analysis cache. Three summary cards show memory/maxmemory, key hit rate,
and evictions, with links preserving the selected installation and time range.
### What lives in each instance

With the dedicated analysis cache enabled, each registry uses two separate
Redis/Valkey instances. All scanner pods share both; they store different data.

| Instance | What it stores | Dashboard row |
| --- | --- | --- |
| Existing Harbor Redis/Valkey | Adapter job queue, delivery leases, job state, and scan reports awaiting retrieval by Harbor | Redis job/report client pool |
| Dedicated scanner Redis/Valkey | Reusable image/layer analysis, replacing the local `fanal.db` analysis cache | Redis / Valkey analysis cache |

In the reference deployment, three scanner pods share logical DB 5 on Harbor's
Valkey for jobs/reports and a separate scanner Valkey for analysis. The
deployment selects DB 5; other deployments can choose a different number.

The bundled cache uses 512 MiB maxmemory, allkeys-lru eviction and a 7-day
cache TTL (`trivy.cacheTTL: 168h`) by default, matching that deployment. TTL is
set on writes; reads do not extend it. Evicted analysis can be recomputed.
A separate instance keeps cache eviction from removing pending jobs or reports.
Logical databases on Harbor's instance share its memory limit and eviction
policy. Configure these values
for your workload; the memory panel shows the selected server's actual limit.

The vulnerability database and Java package index still live on each scanner
pod's own PVC. Redis analysis caching does not replace these local databases.
The adapter's Redis client-pool metrics cover job/report connections. Trivy CLI
cache connections are separate. Harbor accesses PostgreSQL directly; the adapter
has no PostgreSQL connection.

### Reading the cache panels

Memory usage turns orange at 80% and red at 95% of Redis `maxmemory`. The
container memory limit is configured separately. A zero configured limit displays No maxmemory. Cache
hit rate displays No lookups when idle and Unknown for missing telemetry.
Evictions are counted over the selected range and highlighted for investigation;
some eviction is normal for a bounded cache. Key lookup hit rate is different
from client connection-pool hits. Command execution time excludes network and
pool waits. Shared servers include traffic and memory from every workload.

The panels use metrics from the exporter's
[reference dashboard](https://github.com/oliver006/redis_exporter/blob/master/contrib/grafana_prometheus_redis_dashboard.json),
scoped to the selected installation and shown per server. Idle, unknown and
unlimited values have separate display states.

## Trivy dashboard: select one installation

Select a Prometheus data source, Cluster, Namespace, then Scanner.
Each selector defaults to its first alphabetical result and accepts one value.
There is no All option. The Scanner is the Kubernetes Service name, so
several scanner deployments in one namespace remain separate while their replicas
are shown together. Save a preferred selection in your own dashboard copy or use
Grafana's URL variable parameters for a bookmark.

Queries require `cluster`, `namespace`, `scanner`, and, for pod panels, `pod` labels.
The ServiceMonitor adds `scanner` from the discovered Service name. Set
`metrics.serviceMonitor.cluster` to a unique cluster name unless your query data
source already supplies a consistent `cluster` label. Prometheus external labels
are available through remote storage/federation, but are not automatically labels
on samples queried directly from that Prometheus. Use the same cluster label on
kubelet, kube-state-metrics, Harbor, Redis, and Loki data. Custom ServiceMonitor
relabelings run after the defaults and can override them.

For a standalone scrape configuration, reproduce these labels, including `scanner`
on the `up` series. See the [metrics catalog](../../../docs/metrics.md).
No matches means the required labels, scrape, or adapter version need attention;
an empty chart does not imply zero failures or zero resource use.

## What the panels mean

Panel tooltips summarize the measurement and what to investigate. Collection
requirements and missing-data guidance are documented below. p95 estimates the value below which
95% of observations fall; it is calculated from histogram buckets, not an exact
maximum. Rate and percentile panels use a recent sliding window, while the
completed/failed execution totals use the selected dashboard range. Counter
increases are estimates between scrapes and can produce fractional totals.
Event rates use per-minute units (`rate(...) * 60`) because scanner workloads
often produce fewer than one event per second. The averaging window stays the
same. Completed/failed totals cover the selected range, and payload traffic is
measured in bytes per second.

Outcome panels use green for success and red for errors. Blue identifies normal
waiting or skipped work; orange highlights fallbacks and missing records for
investigation. Database rows use one table row per replica, with availability,
update policy, content age, last download and next update check as columns.
Missing vulnerability data is red; an absent Java index is neutral. Unavailable
metrics or failed scrapes produce Unknown, not a healthy state. Display labels
shorten `harbor-scanner-trivy-0` to `trivy-0`; log discovery retains full pod names.

Content age measures the installed content's build age. The vulnerability
DB turns orange at 12 hours and red at 24 hours; the Java index turns orange at
48 hours and red at 72 hours. These thresholds express a dashboard freshness policy. Crossing one does not
establish that Trivy missed an update deadline or that a download failed. Last download is
the time since the pod downloaded its copy. Next update check uses the
installed metadata's threshold; it does not schedule a download or include all
of Trivy's recent-download checks.

The Database freshness history row has a content-age chart and a file-presence
timeline for each database. Age rises between updates and drops when newer
content is installed. Compare replicas while they are running scans that use
the database; idle pods can keep older copies.

History queries combine scrape instances belonging to the same pod, so restarts
keep one series per replica. Presence checks confirm the files and metadata
exist; they cannot establish database integrity. Gaps indicate missing observations.

The paths in the tooltips are relative to Trivy's cache directory:

| File | Purpose |
| --- | --- |
| `db/trivy.db` | Local vulnerability reference data |
| `java-db/trivy-java.db` | Local index for identifying Java packages |
| `fanal/fanal.db` | Local reusable image/layer analysis; replaced by Redis caching |

Disk metric collection shows one row per pod, with each collector's status and
time since its last success. If that time keeps rising, its measurements have
stopped refreshing. Optional file sizes show Not reported when telemetry is
missing; check whether collection is disabled.

The View history link opens the disk-collection timeline under Monitoring
diagnostics. A failed collection means the measurements are unavailable.
Diagnosing a disk failure requires further checks.

Cache summary cards hide the instance name when showing one value and retain
names for multiple instances. When the adapter reports filesystem caching,
these cards show Filesystem cache, excluding unrelated Redis server metrics.

Prometheus query Min step is set to `1m` on rate-based targets. This makes
Grafana's `$__rate_interval` at least four minutes, allowing rate calculations
with one-minute scrapes even when viewing the last 15 minutes. If your scrape
interval is longer, increase those targets' Min step to match. Dashboard refresh
frequency does not change how often Prometheus collects samples.

- Overview and Runtime: replica health, actual completed/failed executions,
  CPU, memory, throttling, restarts, OOM termination state, and child peak RSS.
  Pod resource charts include sidecars and require kubelet/cAdvisor and
  kube-state-metrics. They join discovered scanner pods; unrelated pods are excluded.
  Child RSS is sampled when a child exits and is not current process memory.
- Scan pipeline: the three panels follow Harbor queue → adapter queue → active
  worker. Harbor shows the current age of its next queued IMAGE_SCAN task; adapter
  wait is p95 among tasks that first started in the recent window; worker age is
  elapsed time of the oldest currently executing task per replica. These measure
  different populations and cannot be added into an end-to-end duration. Harbor
  context can include other scanner registrations in the same installation.
- Scanning and workers: completed execution attempts, dispatch decisions,
  concurrency, failure categories, CLI exits and SBOM reuse decisions. Retries
  count as additional attempts. Unacknowledged deliveries include queued and
  in-progress work; the shared queue is sampled between scans and aggregated with
  `max`, so busy workers can leave an older observation. CLI duration covers one
  child process; worker duration also includes report processing and persistence.
  SBOM accessory reuse is separate from the Trivy analysis-cache hit rate.
- Vulnerability database / Java package index: separate expanded rows show
  downloaded database presence, age, next update,
  and configured update policy. Missing Java DB can
  be normal before Java scanning. Update policy is not proof of a successful download.
  The Java DB identifies Java packages; the vulnerability DB supplies vulnerability
  records. Database age uses the installed metadata's content build timestamp,
  not its download timestamp. Next update is metadata used in update eligibility
  checks, not a promise that a background download will happen at that time.
  Each row filters queries to its own database and keeps replicas separate.
  Monitoring diagnostics shows whether the adapter could read DB/Java metadata
  and how long since that check last succeeded. A missing database can be a valid
  observation. These checks establish monitoring freshness only; database
  integrity, scan success, content age and download age need their own checks.
- Redis / Valkey analysis cache: dedicated server-memory, hit-rate and eviction
  cards link to the Valkey dashboard. Redis job/report client pool has a separate
  row: it measures adapter connections, not Trivy CLI cache connections.
- Filesystem analysis cache: collapsed and shown only when
  `analysis_cache_backend_info{backend="filesystem"}` reports the active backend
  at the selected range's end. Redis, memory, and older adapters without this
  metric show no fanal size, including leftover files from a previous backend.
  The collector skips fanal entirely for non-filesystem backends.
- Local disk: databases and reports: filesystem space/inodes and optional DB
  file sizes. Vulnerability databases, Java indexes and temporary reports still
  need local disk with Redis analysis caching. BoltDB names a storage engine;
  fanal scan analysis and the vulnerability database have different purposes.
  Enable `cacheSizeEnabled` for bounded directory walks. Failed or incomplete
  collections omit sizes instead of publishing partial totals. Filesystem capacity
  belongs to the mount and can include other users of that filesystem. The fill-time
  estimate is a six-hour trend with a minimum sample count, not an enforced quota.
- Reports, persistence, and API: payload sizes/compression, report fetch age and
  retention, storage latency/errors, Redis client pool pressure, HTTP traffic, and
  adapter heap. Applied payload bytes are not Redis resident memory or wire bytes.
  Histograms have no observations until the corresponding operation occurs.
- Optional context: Harbor's IMAGE_SCAN jobservice panels cover the selected
  cluster/namespace and may include other scanner registrations. The analysis-cache
  panels require a Redis/Valkey exporter. Analysis cache (optional) lists exporters
  in the selected namespace; select the analysis-cache server. Server memory includes every workload using that instance; it cannot be
  attributed to this scanner alone.
- Optional logs: select a Loki data source with matching `cluster`, `namespace`,
  and `pod` labels. A hidden pod variable expands the selected scanner's discovered
  pods, including all its replicas. It does not broaden the installation selectors.
  Historical logs of pods that no longer appear in Prometheus discovery are excluded.

Use Harbor for vulnerability inventory and severity counts. Trivy engine phase
timings, cache hit rates, registry transfer/retry metrics and DB download/lock
timings require additional Trivy hooks. CLI duration cannot measure those phases
individually. See [issue #97](https://github.com/container-registry/harbor-scanner-trivy/issues/97)
for the separately scoped engine work.

## When panels are empty

First check Reachable replicas and Instrumented replicas. If gauges work
but most rate/percentile charts are empty, check query Min step against the actual
scrape interval. A one-minute rate window cannot reliably calculate rates from
one-minute samples. Do not replace unknown measurements with zero.

| Panel or group | Expected reason for no value | What to check |
| --- | --- | --- |
| Execution, CLI, report, store, or API p95 | No matching operations in the recent rate window | Activity counters; widen the range to find earlier activity |
| Failure categories | No failure has created a category series yet | Failed executions should confirm zero failures |
| Last container termination was OOM | No recorded termination, or missing kube-state-metrics | Container restarts and Kubernetes termination state |
| Local file sizes | Collection is disabled by default; missing directories or incomplete walks also omit sizes | `metrics.collection.cacheSizeEnabled` and Disk metric collection |
| Filesystem analysis cache | Redis/memory backend, backend metric unavailable, or size collection disabled | Active backend metric and Disk metric collection; no value is expected with Redis |
| Estimated time to full | Fewer than 60 samples, or free space is not declining | Available filesystem space; the trend always looks back six hours |
| Average pool wait | No requests waited for a pool connection, so the average is undefined | Redis pool timeouts and connection counts |
| Analysis cache summary | No exporter was discovered, or the selected exporter is unavailable | Select the analysis-cache exporter; job/report Redis is separate |
| Database age / next update | Database or required metadata timestamp is missing | Database presence and DB metadata checks |
| Pod, Harbor, or log panels | Their separate metric/log source is unavailable or labels do not match | cAdvisor, kube-state-metrics, Harbor scraping, or Loki labels |

## Sources for the descriptions

The operational metrics are implemented by this adapter around the Trivy CLI;
they are not Trivy Operator vulnerability-inventory metrics. Tooltips follow the
[adapter metrics catalog](../../../docs/metrics.md) and its
[collection implementation](../../../pkg/metrics/background.go), together with
these upstream references:

| Subject | Reference |
| --- | --- |
| Vulnerability DB, Java package index, update flags | [Trivy databases](https://trivy.dev/docs/latest/configuration/db/) |
| Analysis cache contents and local/Redis backends | [Trivy cache](https://trivy.dev/docs/latest/configuration/cache/) |
| Offline scanning and external database access | [Trivy connectivity](https://trivy.dev/docs/latest/advanced/air-gap/) |
| Database metadata timestamps | [Trivy DB metadata](https://github.com/aquasecurity/trivy-db/blob/main/pkg/metadata/metadata.go) |
| Percentile estimates | [Prometheus histograms](https://prometheus.io/docs/practices/histograms/) |
| Rate windows and scrape interval | [Grafana Prometheus variables](https://grafana.com/docs/grafana/latest/datasources/prometheus/template-variables/) |
| Empty rate queries | [Grafana Prometheus troubleshooting](https://grafana.com/docs/grafana/latest/datasources/prometheus/troubleshooting/) |
