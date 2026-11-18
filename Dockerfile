# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=rust:1.100.0-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2
ARG CIPHERRUN_VERSION=0.4.0

FROM ${RUST_IMAGE} AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY src ./src
COPY crates ./crates
COPY vendor ./vendor
COPY data ./data
COPY migrations ./migrations
COPY benches ./benches
COPY examples ./examples
COPY tests ./tests
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
