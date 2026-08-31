# Examples

Each directory is a self-contained scenario: a `values.yaml` you can pass to
`helm install -f`, plus a README explaining what it is for and what you have to
create yourself. CI renders every `values*.yaml` under this tree on each chart
change, so none of them can silently rot.

| Example | What it shows |
|---------|---------------|
| [`harbor-integration/`](harbor-integration/) | The default case: adapter alongside a `goharbor/harbor-helm` release, sharing Harbor's Redis |
| [`external-redis/`](external-redis/) | A password-protected Redis whose URL never enters the pod spec |
| [`tls-cert-manager/`](tls-cert-manager/) | HTTPS API with a cert-manager-issued certificate, plus mutual TLS |
| [`flux/`](flux/) | GitOps delivery with FluxCD: digest-pinned image, externally owned Secrets |
| [`air-gapped/`](air-gapped/) | Mirrored registry, no egress to GitHub, pre-seeded Trivy DB |
| [`openshift/`](openshift/) | Letting OpenShift's SCC assign the UID/GID range instead of pinning one |
| [`private-ca/`](private-ca/) | Trusting a private CA for outbound connections to the registry and Redis |
