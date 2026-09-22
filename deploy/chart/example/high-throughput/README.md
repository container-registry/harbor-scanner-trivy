# Multiple pods with Redis

Throughput comes from replicas. Each pod runs one worker and one Trivy
process with its own vulnerability DB volume; `workerConcurrency` other than
`1` is rejected. Two Redis/Valkey connections are involved and must stay
separate:

| Values | Instance | Stores | Eviction |
| --- | --- | --- | --- |
| `redis.*` | Harbor's existing Redis/Valkey (6.2+) | Job queue (Streams), job state, reports | Must not evict |
| `valkey.*` | Dedicated Valkey from this chart | Trivy image/layer analysis shared by all pods | `allkeys-lru`, 512 MiB by default |

With the shared cache, a layer analyzed by one pod is not pulled or analyzed
again by the others.

## Values

[`values.yaml`](values.yaml) runs three pods. Start with two or three and add
pods while CPU, registry bandwidth and the cache have headroom. Scaling up adds
one PVC per pod and a one-time DB download.

The job Redis URL is read from a Secret, so the password never reaches the pod
spec:

```sh
kubectl -n harbor create secret generic harbor-scanner-trivy-redis \
  --from-literal=url='redis://:s3cr3t@harbor-redis:6379/5'
```

Sentinel URLs work for the job connection. For an external or password-protected
analysis cache, TLS, sizing and upgrading from Pub/Sub releases, see the
[scaling guide](../../../../docs/SCALING.md).

## Grafana dashboards

`metrics.grafanaDashboard.enabled` ships the Trivy and Valkey dashboards as a
ConfigMap for the Grafana sidecar; `metrics.serviceMonitor` and
`valkey.metrics.serviceMonitor` feed them (Prometheus Operator required). Enable
the dashboard ConfigMap on one release per Grafana organization. Select Cluster,
Namespace and Scanner, then pick the Valkey exporter under Analysis cache.

![Trivy scanner dashboard with two replicas](../../../../docs/images/grafana-trivy-dashboard.png)

Watch scans per minute, average scan duration, the oldest queued delivery and
cache evictions when deciding whether another pod helps. See the
[dashboard guide](../../dashboards/README.md) for every panel.
