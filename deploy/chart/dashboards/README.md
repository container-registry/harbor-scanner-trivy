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

- **Overview and Runtime:** replica health, actual completed/failed executions,
  CPU, memory, throttling, restarts, OOM termination state, and child peak RSS.
  Pod resource charts include sidecars and require kubelet/cAdvisor and
  kube-state-metrics. They join discovered scanner pods; unrelated pods are excluded.
  Child RSS is sampled when a child exits and is not current process memory.
- **Scanning and workers:** adapter dispatch, wait, execution time, concurrency,
  failure categories, CLI termination reasons, and SBOM reuse/fallback.
  Redis Pub/Sub has no durable adapter queue depth. Harbor scheduling happens
  before the adapter receives a request and is a separate measurement.
- **Database:** vulnerability and Java database presence, age, next update,
  configured update policy, and metadata collection health. Missing Java DB can
  be normal before Java scanning. Update policy is not proof of a successful download.
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
