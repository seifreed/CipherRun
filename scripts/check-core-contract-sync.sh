#!/usr/bin/env bash
set -euo pipefail

root_contract="src/core_contract.rs"
core_contract="crates/cipherrun-core/src/lib.rs"

cmp -s "$root_contract" "$core_contract" || {
    echo "${root_contract} and ${core_contract} must remain identical" >&2
    exit 1
}
printf 'core contract sources are synchronized\n'
