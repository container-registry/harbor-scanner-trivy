# OpenShift

The chart's defaults pin `runAsUser`, `runAsGroup` and `fsGroup` to `10000`.
OpenShift's `restricted-v2` SCC allocates a UID range per namespace and rejects
a pod that asks for a UID outside it, so those defaults have to come off and let
OpenShift assign.

The trap is that Helm **deep-merges** maps from `-f`, so writing a
`podSecurityContext` without those keys does not remove them - the chart's
values survive underneath. They have to be set to `null` explicitly, which is
what the values file here does. Check your work:

```sh
helm template harbor-scanner-trivy . -f values.yaml \
  | grep -A6 'securityContext:'
```

You should see `runAsNonRoot` and `seccompProfile` and nothing else.

```sh
helm install harbor-scanner-trivy \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-trivy \
  --namespace harbor -f values.yaml
```

## Why the image still works unowned

The adapter writes only to the mounted cache volume and `/tmp`. OpenShift runs
the container with an arbitrary UID in the root group (GID 0), and the base
image's `/home/scanner` tree is group-readable, so the binary starts. The cache
volume is the part that needs write access - with the default dynamic
provisioner OpenShift sets ownership from the SCC's `fsGroup` range, which is
why `fsGroup` is left unset rather than pinned.

If your storage class does not honour `fsGroup`, the Trivy DB download fails
with a permission error on `/home/scanner/.cache`. That is a storage problem, not an
SCC one: use a class that supports `fsGroup`, or set `persistence.enabled: false`
and accept re-downloading the DB on every restart.
