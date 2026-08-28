# Registry or Redis behind a private CA

The adapter pulls image layers over TLS, and both it and the Trivy CLI it shells
out to are Go programs. `extraCA` mounts your PEM bundle and points Go's
certificate loader at it, which covers every outbound TLS call either makes: the
registry, a TLS Redis, a proxied Trivy DB source.

```sh
kubectl -n harbor create secret generic corp-ca --from-file=ca.crt=./corp-ca.pem

helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy \
  --namespace harbor -f values.yaml
```

## Why `SSL_CERT_DIR` names two directories

The chart sets `SSL_CERT_DIR=/etc/ssl/certs:/etc/scanner-trivy/extra-ca`.

Go's `crypto/x509` **replaces** its default directory list when `SSL_CERT_DIR`
is set rather than adding to it. Pointing it at the mount alone would drop the
system roots, and the first thing to break would be the Trivy DB download from
`ghcr.io` - which looks like a network fault, not a trust one. Listing
`/etc/ssl/certs` explicitly keeps the public bundle. Order does not matter; a
certificate in either directory is trusted.

## Verifying

```sh
kubectl -n harbor exec sts/harbor-scanner-trivy -- \
  ls /etc/scanner-trivy/extra-ca
kubectl -n harbor logs sts/harbor-scanner-trivy | grep -i "certificate\|x509"
```

An `x509: certificate signed by unknown authority` in the logs means the bundle
is missing the issuer, not that the mount failed.

## A note on the scan cache

`trivy.cacheRedisCACert` takes a **path inside the container**, not a Secret
name. If you use a Redis scan cache with its own CA, mount it yourself with
`extraVolumes`/`extraVolumeMounts` and point that value at the result -
`extraCA` above covers trust for Go's default verification, which is a
different mechanism from Trivy's explicit cache-TLS flags.
