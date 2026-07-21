# Binary is pre-cross-compiled by `task build` into bin/linux-<arch>/.
# TRIVY_VERSION (pinned as TRIVY_BASE_IMAGE_VERSION in versions.env) and
# LPROBE_VERSION (pinned in versions.env) are passed by `task image`; there are
# deliberately no defaults so builds fail loudly without them.
ARG TRIVY_VERSION
ARG LPROBE_VERSION

FROM ghcr.io/fivexl/lprobe:${LPROBE_VERSION} AS lprobe

FROM aquasec/trivy:${TRIVY_VERSION}

# An ARG declared before a FROM is outside of a build stage, so it must be
# redeclared inside the stage to be usable after FROM.
ARG TRIVY_VERSION
ARG TRIVY_COMMIT=unknown
ARG TARGETARCH

LABEL org.opencontainers.image.title="harbor-scanner-trivy" \
      org.opencontainers.image.description="Harbor scanner adapter for Trivy" \
      org.opencontainers.image.source="https://github.com/container-registry/harbor-scanner-trivy" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN addgroup -S scanner && adduser -S -G scanner -h /home/scanner scanner

COPY --from=lprobe /lprobe /lprobe
COPY bin/linux-${TARGETARCH}/scanner-trivy /home/scanner/bin/scanner-trivy

# Overwrite the base image's prebuilt trivy with our source-built binary
# (same pinned version, built by `task build:trivy`); keeps the binary
# CVE-patchable via go mod overrides, same pattern as harbor-next.
COPY bin/linux-${TARGETARCH}/trivy /usr/local/bin/trivy

RUN chown -R scanner:scanner /home/scanner /usr/local/bin/trivy

# Read by GetScannerMetadata() and surfaced as Scanner.Version in the Harbor
# UI; the commit suffix pins the exact source the trivy binary was built from.
ENV TRIVY_VERSION="${TRIVY_VERSION} (${TRIVY_COMMIT})"

EXPOSE 8080
EXPOSE 8443
# Shell form so port and scheme follow SCANNER_API_SERVER_ADDR and the TLS
# config at runtime (exec form gets no env expansion). mTLS via
# SCANNER_API_SERVER_CLIENT_CAS still fails the probe: lprobe has no client
# cert to present.
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD addr="${SCANNER_API_SERVER_ADDR:-:8080}"; \
        /lprobe -port "${addr##*:}" -endpoint /probe/ready ${SCANNER_API_SERVER_TLS_CERTIFICATE:+-tls -tls-no-verify}

USER scanner

ENTRYPOINT ["/home/scanner/bin/scanner-trivy"]
