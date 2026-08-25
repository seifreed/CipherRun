#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all --check
scripts/check-core-contract-sync.sh
scripts/check-cli-contract-sync.sh
scripts/check-data-contract-sync.sh
scripts/check-probes-contract-sync.sh
scripts/check-server-contract-sync.sh
scripts/check-protocol-contract-sync.sh
scripts/check-worker-package.sh
scripts/check-policy-contract-sync.sh
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
cargo audit
cargo deny check
cargo package -p cipherrun-core --locked --allow-dirty
cargo package -p cipherrun-cli --locked --allow-dirty
cargo package -p cipherrun-data --locked --allow-dirty
cargo package -p cipherrun-probes --locked --allow-dirty
cargo package -p cipherrun-server --locked --allow-dirty
cargo package -p cipherrun-policy --locked --allow-dirty
cargo package -p cipherrun-protocol --locked --allow-dirty
cargo package -p cipherrun --locked --allow-dirty
cargo install --path . --locked --root target/install-smoke --force

# Keep the declared MSRV and the two supported feature surfaces executable.
cargo +1.88 check --all-targets --locked
cargo check --no-default-features --locked
cargo check --no-default-features --features api --locked
cargo check --no-default-features --features monitoring --locked
cargo check --no-default-features --features "ct,pqc" --locked
cargo check --no-default-features --features rustls --locked
cargo check --no-default-features --features openssl-legacy --locked
cargo check --no-default-features --features db-sqlite --locked
cargo check --no-default-features --features db-postgres --locked
cargo check --all-features --locked

# The release workflow installs cargo-semver-checks. Local runs remain usable
# without downloading another tool.
if command -v cargo-semver-checks >/dev/null 2>&1; then
    cargo semver-checks check-release
fi
