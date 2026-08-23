#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
cargo audit
cargo deny check
cargo package --locked --allow-dirty
cargo install --path . --locked --root target/install-smoke --force
