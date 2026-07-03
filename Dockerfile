# Binary is pre-cross-compiled by `task build` into bin/linux-<arch>/.
# TRIVY_VERSION is pinned as TRIVY_BASE_IMAGE_VERSION in versions.env and passed
# by `task image`; there is deliberately no default so builds fail loudly without it.
ARG TRIVY_VERSION

FROM aquasec/trivy:${TRIVY_VERSION}

# An ARG declared before a FROM is outside of a build stage, so it must be
# redeclared inside the stage to be usable after FROM.
ARG TRIVY_VERSION
ARG TARGETARCH

LABEL org.opencontainers.image.title="harbor-scanner-trivy" \
      org.opencontainers.image.description="Harbor scanner adapter for Trivy" \
      org.opencontainers.image.source="https://github.com/container-registry/harbor-scanner-trivy" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN adduser -u 10000 -D -g '' scanner scanner

COPY bin/linux-${TARGETARCH}/scanner-trivy /home/scanner/bin/scanner-trivy

# Overwrite the base image's prebuilt trivy with our source-built binary
# (same pinned version, built by `task build:trivy`); keeps the binary
# CVE-patchable via go mod overrides, same pattern as harbor-next.
COPY bin/linux-${TARGETARCH}/trivy /usr/local/bin/trivy

ENV TRIVY_VERSION=${TRIVY_VERSION}

USER scanner

ENTRYPOINT ["/home/scanner/bin/scanner-trivy"]
