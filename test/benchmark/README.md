# SBOM accessory fast-path benchmark

`sbom-accessory-bench.sh` measures what the `SCANNER_TRIVY_USE_SBOM_ACCESSORY`
fast path saves: for each image it times a cold `trivy image` scan (today's
behavior), a cold SBOM generation (`--format spdx-json`, what Harbor stores as
an accessory), and a `trivy sbom` scan of that file (the fast path). It also
verifies both paths report the identical set of `(VulnerabilityID, PkgName)`
pairs.

Requirements: `trivy` and `python3` on PATH, network access to Docker Hub and
the Trivy DB registries.

```bash
# default set: 10 node images + 4 large-SBOM images
./sbom-accessory-bench.sh

# custom set
./sbom-accessory-bench.sh node:22 python:3.13
```

Results land in `./sbom-bench-results/results.csv` (override with `OUT_DIR`);
a markdown table is printed at the end. `PLATFORM` defaults to `linux/amd64`.

Notes on interpretation:

- The cold scan includes pulling layers from the upstream registry. In
  production the adapter pulls from the local Harbor registry, so absolute
  numbers shrink, but layer extraction and analysis still dominate.
- SBOM generation is a one-time cost paid when Harbor generates the accessory
  (for example auto-generate on push). Every subsequent vulnerability scan of
  that artifact pays the `sbom_scan_s` cost instead of `cold_scan_s`.
