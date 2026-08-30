# Changelog

## [0.40.1](https://github.com/container-registry/harbor-scanner-trivy/compare/v0.40.0...v0.40.1) (2026-08-28)


### Bug Fixes

* **build:** apply CVE overrides when building Trivy from source ([#55](https://github.com/container-registry/harbor-scanner-trivy/issues/55)) ([107677e](https://github.com/container-registry/harbor-scanner-trivy/commit/107677e2669ed3a933875022f512dcdafd3d8f1e))
* **deps:** bump Go to 1.26.6 for stdlib vulnerability fixes ([#50](https://github.com/container-registry/harbor-scanner-trivy/issues/50)) ([d69d98d](https://github.com/container-registry/harbor-scanner-trivy/commit/d69d98d03cd6188a4c4b8ae8de7a088977cb3dcd))


### Performance Improvements

* **redis:** split scan report into its own key ([#43](https://github.com/container-registry/harbor-scanner-trivy/issues/43)) ([dee1707](https://github.com/container-registry/harbor-scanner-trivy/commit/dee1707e740dad6c13ce74079d38ac05efffd7e7))


### Documentation

* restructure README around fork rationale and measured performance ([#53](https://github.com/container-registry/harbor-scanner-trivy/issues/53)) ([039fcfb](https://github.com/container-registry/harbor-scanner-trivy/commit/039fcfb4875410da6f4d16d36b132255afbfb92a))

## [0.40.0](https://github.com/container-registry/harbor-scanner-trivy/compare/v0.39.1...v0.40.0) (2026-07-21)


### Features

* **build:** include Trivy commit hash in scanner metadata ([#35](https://github.com/container-registry/harbor-scanner-trivy/issues/35)) ([5e93741](https://github.com/container-registry/harbor-scanner-trivy/commit/5e9374182943fabb2cb9cd4448d8759b85728ccc))
* Scan pre-existing SBOM accessory instead of image layers ([#38](https://github.com/container-registry/harbor-scanner-trivy/issues/38)) ([7d97d36](https://github.com/container-registry/harbor-scanner-trivy/commit/7d97d36b5a34e1335a7613143dcd366a33ddb16c))


### Bug Fixes

* **docker:** derive HEALTHCHECK port and scheme from server config ([#34](https://github.com/container-registry/harbor-scanner-trivy/issues/34)) ([55d74dc](https://github.com/container-registry/harbor-scanner-trivy/commit/55d74dcd67f98d13ced413b8cfec83c433dd7c0a))

## [0.39.1](https://github.com/container-registry/harbor-scanner-trivy/compare/v0.39.0...v0.39.1) (2026-07-12)


### Bug Fixes

* Add lprobe and align image user with harbor-next trivy-adapter ([#33](https://github.com/container-registry/harbor-scanner-trivy/issues/33)) ([78eb9d3](https://github.com/container-registry/harbor-scanner-trivy/commit/78eb9d380a1354527b323218f2c9c7f14f111560))
* **ci:** bump Go to 1.26.5 to resolve GO-2026-5856 ([#32](https://github.com/container-registry/harbor-scanner-trivy/issues/32)) ([344d2e4](https://github.com/container-registry/harbor-scanner-trivy/commit/344d2e46de76c5fcd8f054a50e34e12997f34391))


### Performance Improvements

* add benchmark tests for trivy and scan packages ([#12](https://github.com/container-registry/harbor-scanner-trivy/issues/12)) ([e053ae4](https://github.com/container-registry/harbor-scanner-trivy/commit/e053ae4c8e85d71aca02dd37315fd14891c3e55f))
* **redis:** gzip-compress stored scan job values ([#31](https://github.com/container-registry/harbor-scanner-trivy/issues/31)) ([df82d98](https://github.com/container-registry/harbor-scanner-trivy/commit/df82d9869cdf5836cdbe8c6649841fcd96446640))

## [0.39.0](https://github.com/container-registry/harbor-scanner-trivy/compare/v0.38.1...v0.39.0) (2026-07-03)


### Features

* build Trivy from source and publish adapter and Trivy binaries ([#24](https://github.com/container-registry/harbor-scanner-trivy/issues/24)) ([0b3893e](https://github.com/container-registry/harbor-scanner-trivy/commit/0b3893e2f835ca9ed38bcf3cc76b6649bcd47bfb))

## [0.38.1](https://github.com/container-registry/harbor-scanner-trivy/compare/v0.38.0...v0.38.1) (2026-07-03)


### Bug Fixes

* validate layer media types and return structured scan errors ([4fd69a4](https://github.com/container-registry/harbor-scanner-trivy/commit/4fd69a409468695aeb9c9acc07962cc539f6b981))


### Code Refactoring

* rename Go module to github.com/container-registry/harbor-scanner-trivy ([#20](https://github.com/container-registry/harbor-scanner-trivy/issues/20)) ([3aecb90](https://github.com/container-registry/harbor-scanner-trivy/commit/3aecb90cdf0475bd9301cc9d80de996f2bd8b07a))
