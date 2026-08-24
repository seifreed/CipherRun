#!/usr/bin/env bash
set -euo pipefail

root_contract="src/protocols/model.rs"
published_contract="crates/cipherrun-protocol/src/model.rs"

if ! cmp -s "$root_contract" "$published_contract"; then
    echo "Protocol contract drift detected: $root_contract != $published_contract" >&2
    diff -u "$root_contract" "$published_contract" >&2 || true
    exit 1
fi

echo "Protocol contract sync: OK"
