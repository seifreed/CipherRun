#!/usr/bin/env bash
set -euo pipefail

results=${RESULTS_DIR:-/results}/differential
mkdir -p "$results"

targets=${DIFFERENTIAL_TARGETS:-"legacy-tls legacy11-tls weak-tls modern-tls"}
for target in $targets; do
    status=0
    timeout 180 sslyze --quiet --json_out "$results/$target.sslyze.json" "$target:443" \
        >"$results/$target.sslyze.txt" 2>&1 || status=$?
    printf '%s\n' "$status" >"$results/$target.sslyze.exit"
    test -s "$results/$target.sslyze.json"
done

echo "SSLyze differential fixtures passed; artifacts: $results"
