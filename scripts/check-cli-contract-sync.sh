#!/usr/bin/env bash
set -euo pipefail

root_contract="src/commands/contract.rs"
published_contract="crates/cipherrun-cli/src/lib.rs"

if ! diff -u <(tail -n +1 "$root_contract") <(tail -n +3 "$published_contract"); then
    echo "CLI contract drift detected: $root_contract != $published_contract" >&2
    exit 1
fi

echo "CLI contract sync: OK"
