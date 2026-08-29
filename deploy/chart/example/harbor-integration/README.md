# Alongside a goharbor/harbor-helm release

Deploy the adapter into the same namespace as Harbor and point it at Harbor's
own Redis. The chart already assumes this shape, and the values file adjusts it
to a concrete cluster: it overrides the Redis host and picks a dedicated
database number so the adapter's keys do not share space with Harbor's.

```sh
helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy \
  --namespace harbor \
  -f values.yaml
```

Then register the scanner in Harbor (Administration -> Interrogation Services ->
Scanners -> NEW SCANNER) with the endpoint the chart prints on install:

```
http://harbor-scanner-trivy.harbor.svc:8080
```

## What you need first

- A Harbor release whose Redis Service is `harbor-redis`. Confirm the name -
  the goharbor chart calls it `<release>-redis`, so a release named `harbor`
  gives `harbor-redis`, and the older `<release>-harbor-redis` naming is still
  out there. `kubectl -n harbor get svc | grep redis` settles it.
- Redis database `5` free for the adapter. Harbor itself uses `0`-`4`.
