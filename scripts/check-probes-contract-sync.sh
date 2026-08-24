#!/usr/bin/env bash
set -euo pipefail

root_contract="src/scanner/contract.rs"
published_contract="crates/cipherrun-probes/src/lib.rs"

if ! diff -u <(tail -n +3 "$root_contract") <(tail -n +5 "$published_contract"); then
    echo "Probe contract drift detected: $root_contract != $published_contract" >&2
    exit 1
fi

echo "Probe contract sync: OK"
