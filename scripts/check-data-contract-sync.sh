#!/usr/bin/env bash
set -euo pipefail

root_contract="src/compliance/contract.rs"
published_contract="crates/cipherrun-data/src/lib.rs"

if ! diff -u <(tail -n +3 "$root_contract") <(tail -n +5 "$published_contract"); then
    echo "Data contract drift detected: $root_contract != $published_contract" >&2
    exit 1
fi

echo "Data contract sync: OK"
