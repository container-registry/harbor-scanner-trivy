# HTTPS API with a cert-manager certificate

cert-manager writes a `kubernetes.io/tls` Secret; `api.tls.existingSecret`
consumes it directly, so no certificate material is ever stored in values or in
Git. The Certificate itself rides along in `extraManifests`, which means one
`helm install` produces both.

The SAN must be the in-cluster Service DNS name Harbor will connect to, or
Harbor rejects the scanner with a certificate error.

```sh
helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy \
  --namespace harbor -f values.yaml
```

Register the scanner with the `https://` endpoint. Harbor must trust the issuing
CA - either add it to Harbor's trust store, or tick "Skip certificate
verification" on the scanner registration (test clusters only).

## Mutual TLS

Uncommenting the `clientCAs` block makes the adapter *require* a client
certificate: `SCANNER_API_SERVER_CLIENT_CAS` switches the listener to
`RequireAndVerifyClientCert`. Harbor must then be configured to present a
client certificate, otherwise every scan request fails the TLS handshake. The
chart cannot enumerate the keys of a Secret it does not own, so
`clientCAs.keys` has to name them.

## What you need first

- cert-manager installed, with an Issuer or ClusterIssuer named below.
