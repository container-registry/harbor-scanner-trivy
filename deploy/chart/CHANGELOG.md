# Changelog

## [1.1.1](https://github.com/container-registry/harbor-scanner-trivy/compare/chart-v1.1.0...chart-v1.1.1) (2026-09-24)


### Documentation

* merge Redis examples into one multi-pod high-throughput example ([#120](https://github.com/container-registry/harbor-scanner-trivy/issues/120)) ([8f8f25c](https://github.com/container-registry/harbor-scanner-trivy/commit/8f8f25c3edc2b676f0c28c71ca1f6f0c3f06141c))

## [1.1.0](https://github.com/container-registry/harbor-scanner-trivy/compare/chart-v1.0.1...chart-v1.1.0) (2026-09-21)


### Features

* **chart:** add Trivy and Valkey operational dashboards ([#99](https://github.com/container-registry/harbor-scanner-trivy/issues/99)) ([8cb1d92](https://github.com/container-registry/harbor-scanner-trivy/commit/8cb1d9261f64f2ff77cca73f9e79508689918fbe))
* **metrics:** classify scan failures, real readiness, queue self-recovery and engine defaults ([#110](https://github.com/container-registry/harbor-scanner-trivy/issues/110)) ([858421c](https://github.com/container-registry/harbor-scanner-trivy/commit/858421c001baa144c38cfd32c614d4ed693ce4fe))
* **perf:** Trivy scans with durable workers and dedicated Valkey ([#106](https://github.com/container-registry/harbor-scanner-trivy/issues/106)) ([903c5e2](https://github.com/container-registry/harbor-scanner-trivy/commit/903c5e252d6c6ac6da2ce48e44a4202adfdb76a4))


### Bug Fixes

* **chart:** let the chart release PR restamp the version in the generated README ([#72](https://github.com/container-registry/harbor-scanner-trivy/issues/72)) ([9102e9b](https://github.com/container-registry/harbor-scanner-trivy/commit/9102e9b77f39253b25f9b36ec01492a00762c6c8))
* **chart:** reject log levels the adapter does not understand ([#82](https://github.com/container-registry/harbor-scanner-trivy/issues/82)) ([e4ec360](https://github.com/container-registry/harbor-scanner-trivy/commit/e4ec36008293e1525d073231df3ad2d4b7a8056d))


### Documentation

* drop obsolete README content and fix config table facts ([#80](https://github.com/container-registry/harbor-scanner-trivy/issues/80)) ([bd4dd61](https://github.com/container-registry/harbor-scanner-trivy/commit/bd4dd6116c44d188eccb05a55e3f7c8dfedc7830))


### Miscellaneous

* release adapter 0.41.0 ([#65](https://github.com/container-registry/harbor-scanner-trivy/issues/65)) ([52ba524](https://github.com/container-registry/harbor-scanner-trivy/commit/52ba52444399e378a250a234c07f253a82333bae))
* release adapter 0.42.0 ([#116](https://github.com/container-registry/harbor-scanner-trivy/issues/116)) ([10c8d11](https://github.com/container-registry/harbor-scanner-trivy/commit/10c8d11062cb7a0e2632ec2f0fb844deca4a1184))

## [1.0.1](https://github.com/container-registry/harbor-scanner-trivy/compare/chart-v1.0.0...chart-v1.0.1) (2026-08-31)


### Bug Fixes

* **chart:** make the values schema subchart-safe (enabled flag, open global) ([#68](https://github.com/container-registry/harbor-scanner-trivy/issues/68)) ([c217d2f](https://github.com/container-registry/harbor-scanner-trivy/commit/c217d2fc9290efecbde3b565ba57f32f4ce315ef))

## [1.0.0](https://github.com/container-registry/harbor-scanner-trivy/compare/chart-v1.0.0...chart-v1.0.0) (2026-08-31)


### Features

* **chart:** production-ready chart with an independent release line ([fa76805](https://github.com/container-registry/harbor-scanner-trivy/commit/fa768059b4f418419dddf8aaf20030ab08b7d215))

## Changelog

Chart releases are cut by release-please from conventional commits scoped to
`deploy/chart`, and tagged `chart-vX.Y.Z`. The chart is versioned
independently of the adapter, whose changelog is [`/CHANGELOG.md`](../../CHANGELOG.md).

Release-please appends each release below this line.
