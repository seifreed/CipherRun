#!/usr/bin/env bash
set -euo pipefail

results=${RESULTS_DIR:-/results}/differential
mkdir -p "$results"

targets=${DIFFERENTIAL_TARGETS:-"legacy-tls legacy11-tls weak-tls modern-tls"}
for target in $targets; do
    status=0
    timeout 180 java -jar /apps/TLS-Server-Scanner.jar \
        -connect "$target:443" -scanDetail QUICK -reportDetail NORMAL -noColor \
        >"$results/$target.tls-scanner.txt" 2>&1 || status=$?
    printf '%s\n' "$status" >"$results/$target.tls-scanner.exit"
    test -s "$results/$target.tls-scanner.txt"
done

echo "TLS-Scanner differential fixtures passed; artifacts: $results"
