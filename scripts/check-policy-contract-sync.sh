#!/usr/bin/env bash
set -euo pipefail

root_contract="src/policy/contract.rs"
published_contract="crates/cipherrun-policy/src/lib.rs"

if ! diff -u <(tail -n +3 "$root_contract") <(tail -n +5 "$published_contract"); then
    echo "Policy contract drift detected: $root_contract != $published_contract" >&2
    exit 1
fi

echo "Policy contract sync: OK"
