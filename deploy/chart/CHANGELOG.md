# Changelog

## [1.0.2](https://github.com/container-registry/harbor-scanner-trivy/compare/chart-v1.0.1...chart-v1.0.2) (2026-09-03)


### Bug Fixes

* **chart:** let the chart release PR restamp the version in the generated README ([#72](https://github.com/container-registry/harbor-scanner-trivy/issues/72)) ([9102e9b](https://github.com/container-registry/harbor-scanner-trivy/commit/9102e9b77f39253b25f9b36ec01492a00762c6c8))
* **chart:** reject log levels the adapter does not understand ([#82](https://github.com/container-registry/harbor-scanner-trivy/issues/82)) ([e4ec360](https://github.com/container-registry/harbor-scanner-trivy/commit/e4ec36008293e1525d073231df3ad2d4b7a8056d))


### Documentation

* drop obsolete README content and fix config table facts ([#80](https://github.com/container-registry/harbor-scanner-trivy/issues/80)) ([bd4dd61](https://github.com/container-registry/harbor-scanner-trivy/commit/bd4dd6116c44d188eccb05a55e3f7c8dfedc7830))

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
