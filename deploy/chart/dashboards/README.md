# Harbor Trivy Scanner dashboard

[trivy.json](trivy.json) is the canonical Grafana dashboard. Import this file
manually, or let a Grafana dashboard sidecar load the chart's optional ConfigMap.
The chart embeds the same JSON without evaluating Grafana's template expressions.
Provision it once per Grafana organization: all scanner releases use the same UID.

## Setup

Use an adapter image containing the operational metrics implementation from
[PR #98](https://github.com/container-registry/harbor-scanner-trivy/pull/98).
Older images, including v0.40.1, expose Go/process metrics but cannot populate the
new scanner panels. Until that implementation is released, explicitly select an
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
The ConfigMap does not install Grafana or its data sources.

## Select one installation

Select a Prometheus data source, **Cluster**, **Namespace**, then **Scanner**.
Each selector picks its first alphabetical result initially and allows exactly
one value, with no All option. The Scanner is the Kubernetes Service name, so
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
requirements and missing-data guidance are documented below. **p95** estimates the value below which
95% of observations fall; it is calculated from histogram buckets, not an exact
maximum. Rate and percentile panels use a recent sliding window, while the
completed/failed execution totals use the selected dashboard range. Counter
increases are estimates between scrapes and can produce fractional totals.
Event rates use per-minute units (`rate(...) * 60`) for readability at scanner
workload volumes. They retain the same averaging window; completed/failed totals
still cover the selected range. Payload traffic remains bytes per second.

Outcome panels use green for success and red for errors. Blue identifies normal
waiting or skipped work; orange highlights fallbacks and missing records for
investigation. Database availability and update policy use current-status cards
per replica. Missing vulnerability data is red; an absent Java index is neutral.
Unavailable metrics or failed scrapes produce **Unknown**, not a healthy state.
Collection health and OOM termination history retain named states.
Status timelines sit in the left column; metadata collection matches the size of
the neighboring metadata snapshot-age panel. Each database
row places all five cards side by side: availability, update policy, content age,
last database download, and next update check. Green means healthy or present,
blue means enabled, red marks failures, and gray marks neutral or unknown states.

**Content age** shows the current age per replica, without a sparkline. The
vulnerability database turns orange at 12 hours and red at 24 hours; the Java
package index turns orange at 48 hours and red at 72 hours. Missing telemetry
remains gray / **Unknown**. These are dashboard freshness thresholds, not Trivy
limits or proof of a failed update. They allow time beyond the upstream build
schedules: [every six hours for vulnerability data](https://github.com/aquasecurity/trivy-db/blob/main/.github/workflows/cron.yml)
and [daily for the Java index](https://github.com/aquasecurity/trivy-java-db/blob/main/.github/workflows/cron.yml).
The original content-age graphs remain available through **View history**.

**Next update check** shows time until the installed metadata's update threshold,
**Eligible now**, or **Updates disabled**. It does not schedule a download.
**Last database download** shows the age of the local download separately from
the content's build age. **Storage metrics collection** lists each collector's
latest result and time since its last success. An unknown optional cache-size
collector may be disabled; missing telemetry alone cannot establish that.

Use each current-status panel's **View history** link, or expand **Database and
storage history** at the bottom, to investigate past transitions. These views
retain the selected installation and time range.

Prometheus query **Min step** is set to `1m` on rate-based targets. This makes
Grafana's `$__rate_interval` at least four minutes, allowing rate calculations
with one-minute scrapes even when viewing the last 15 minutes. If your scrape
interval is longer, increase those targets' Min step to match. Dashboard refresh
frequency does not change how often Prometheus collects samples.

- **Overview and Runtime:** replica health, actual completed/failed executions,
  CPU, memory, throttling, restarts, OOM termination state, and child peak RSS.
  Pod resource charts include sidecars and require kubelet/cAdvisor and
  kube-state-metrics. They join discovered scanner pods; unrelated pods are excluded.
  Child RSS is sampled when a child exits and is not current process memory.
- **Scanning and workers:** adapter dispatch, wait, execution time, concurrency,
  failure categories, CLI termination reasons, and SBOM reuse/fallback.
  Redis Pub/Sub has no durable adapter queue depth. Harbor scheduling happens
  before the adapter receives a request and is a separate measurement.
- **Vulnerability database / Java package index:** separate expanded rows show
  downloaded database presence, age, next update,
  configured update policy, and metadata collection health. Missing Java DB can
  be normal before Java scanning. Update policy is not proof of a successful download.
  The Java DB identifies Java packages; the vulnerability DB supplies vulnerability
  records. Database age uses the installed metadata's content build timestamp,
  not its download timestamp. Next update is metadata used in update eligibility
  checks, not a promise that a background download will happen at that time.
  Each row filters queries to its own database and keeps replicas separate.
  **Database monitoring health** shows the shared metadata collector once.
  The local **Analysis cache (BoltDB)** stores reusable scan analysis and appears
  under Cache and storage. BoltDB is a storage engine, not a description of a
  database's contents; Trivy also uses it for the vulnerability database.
- **Cache and storage:** filesystem space/inodes and optional local cache sizes.
  Enable `cacheSizeEnabled` for bounded directory walks. Failed or incomplete
  collections omit sizes instead of publishing partial totals. Filesystem capacity
  belongs to the mount and can include other users of that filesystem. The fill-time
  estimate is a six-hour trend with a minimum sample count, not an enforced quota.
- **Reports, persistence, and API:** payload sizes/compression, report fetch age and
  retention, storage latency/errors, Redis client pool pressure, HTTP traffic, and
  adapter heap. Applied payload bytes are not Redis resident memory or wire bytes.
  Histograms have no observations until the corresponding operation occurs.
- **Optional context:** Harbor's IMAGE_SCAN jobservice panels cover the selected
  cluster/namespace and may include other scanner registrations. Redis server memory
  requires a Redis exporter and an explicit **Redis service** value; it is shared
  server memory, not this scanner's attributed memory.
- **Optional logs:** select a Loki data source with matching `cluster`, `namespace`,
  and `pod` labels. A hidden pod variable expands the selected scanner's discovered
  pods, including all its replicas. It does not broaden the installation selectors.
  Historical logs of pods that no longer appear in Prometheus discovery are excluded.

No vulnerability inventory or severity counts are included. Use Harbor for those.
Trivy engine phase timings, cache hit rates, registry transfer/retry metrics, and
DB download/lock timings require additional Trivy hooks and are not inferred from
CLI duration. See [issue #97](https://github.com/container-registry/harbor-scanner-trivy/issues/97)
for the separately scoped engine work.

## When panels are empty

First check **Reachable replicas** and **Instrumented replicas**. If gauges work
but most rate/percentile charts are empty, check query Min step against the actual
scrape interval. A one-minute rate window cannot reliably calculate rates from
one-minute samples. Do not replace unknown measurements with zero.

| Panel or group | Expected reason for no value | What to check |
| --- | --- | --- |
| Execution, CLI, report, store, or API p95 | No matching operations in the recent rate window | Activity counters; widen the range to find earlier activity |
| Failure categories | No failure has created a category series yet | Failed executions should confirm zero failures |
| Last container termination was OOM | No recorded termination, or missing kube-state-metrics | Container restarts and Kubernetes termination state |
| Local cache footprint | Collection is disabled by default; missing directories or incomplete walks also omit sizes | `metrics.collection.cacheSizeEnabled` and Storage collection status |
| Estimated time to full | Fewer than 60 samples, or free space is not declining | Available filesystem space; the trend always looks back six hours |
| Average pool wait | No requests waited for a pool connection, so the average is undefined | Redis pool timeouts and connection counts |
| Redis server memory | Redis service selector is blank or its exporter is unavailable | Select the actual exporter Service; memory may include other workloads |
| Database age / next update | Database or required metadata timestamp is missing | Database presence and Metadata collection status |
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
