# Air-gapped install

Two independent things have to stop reaching the internet:

1. **The adapter image.** `global.imageRegistry` repoints it at your mirror in
   one place, preserving the repository path
   (`<mirror>/8gcr/harbor-scanner-trivy`).
2. **The Trivy databases.** Trivy pulls `trivy-db` and `trivy-java-db` from
   GHCR on start and every 12 hours. Point `trivy.dbRepository` /
   `trivy.javaDBRepository` at mirrored OCI repositories, or set
   `skipUpdate` / `skipJavaDBUpdate` and mount pre-seeded databases yourself.

`offlineScan` is a third, separate switch: it stops Trivy making external API
calls while resolving dependencies (Maven Central and friends) during a scan.
Without it a scan still reaches out even when the DB is local.

## Mirroring the databases

```sh
oras copy ghcr.io/aquasecurity/trivy-db:2 registry.internal/trivy-db:2
oras copy ghcr.io/aquasecurity/trivy-java-db:1 registry.internal/trivy-java-db:1
```

## Pre-seeded databases instead of a mirror

With `skipUpdate: true`, the files must already exist on the cache volume:

- `/home/scanner/.cache/trivy/db/trivy.db` (plus `metadata.json`)
- `/home/scanner/.cache/trivy/java-db/trivy-java.db` (plus `metadata.json`)

An `initContainers` entry that copies them from an image or an object store is
the usual way; the cache volume is mounted at `/home/scanner/.cache` in the
init container too if you add the mount.

Note that a stale database silently produces stale scan results, so whichever
route you take needs its own refresh schedule.
