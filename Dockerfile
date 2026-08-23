# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG CIPHERRUN_VERSION=0.3.2

FROM ${RUST_IMAGE} AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY data ./data
COPY migrations ./migrations
COPY benches ./benches
RUN cargo build --release --locked && strip target/release/cipherrun

FROM ${RUNTIME_IMAGE}
ARG CIPHERRUN_VERSION
LABEL org.opencontainers.image.title="CipherRun" \
      org.opencontainers.image.description="Production CipherRun TLS scanner" \
      org.opencontainers.image.source="https://github.com/seifreed/cipherrun" \
      org.opencontainers.image.version="${CIPHERRUN_VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

COPY --from=builder --chown=65532:65532 /build/target/release/cipherrun /usr/local/bin/cipherrun

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["/usr/local/bin/cipherrun", "--version"]
ENTRYPOINT ["/usr/local/bin/cipherrun"]
CMD ["--help"]
