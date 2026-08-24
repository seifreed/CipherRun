#!/bin/bash
set -euo pipefail

results=${RESULTS_DIR:-/results}/differential
mkdir -p "$results"

scan_fixture() {
    local target=$1
    local json="$results/$target.cipherrun.json"

    local exit_code=0
    cipherrun --allow-private --profile safe --overwrite --json "$json" "$target:443" \
        >"$results/$target.cipherrun.txt" 2>&1 || exit_code=$?
    if (( exit_code > 1 )); then
        echo "CipherRun failed for $target with exit code $exit_code" >&2
        return "$exit_code"
    fi
    sslscan --no-colour "$target:443" >"$results/$target.sslscan.txt" 2>&1 || true
    timeout 180 testssl.sh --protocols --warnings off --color 0 "$target:443" \
        >"$results/$target.testssl.txt" 2>&1 || true
    echo | openssl s_client -connect "$target:443" \
        >"$results/$target.openssl.txt" 2>&1
}

scan_fixture legacy-tls
scan_fixture weak-tls
scan_fixture modern-tls

jq -e '.protocols[] | select(.protocol == "TLS10" and .supported == true)' \
    "$results/legacy-tls.cipherrun.json" >/dev/null
jq -e 'all(.protocols[]; .protocol != "TLS12" or .supported == false)' \
    "$results/legacy-tls.cipherrun.json" >/dev/null
jq -e '.protocols[] | select(.protocol == "TLS12" and .supported == true)' \
    "$results/weak-tls.cipherrun.json" >/dev/null
jq -e 'all(.protocols[]; .protocol != "TLS13" or .supported == false)' \
    "$results/weak-tls.cipherrun.json" >/dev/null
jq -e '.protocols[] | select(.protocol == "TLS13" and .supported == true)' \
    "$results/modern-tls.cipherrun.json" >/dev/null
jq -e 'all(.protocols[]; .protocol != "TLS12" or .supported == false)' \
    "$results/modern-tls.cipherrun.json" >/dev/null

awk '$1 == "TLSv1.0" && $2 == "enabled" { found=1 } END { exit !found }' \
    "$results/legacy-tls.sslscan.txt"
awk '$1 == "TLSv1.2" && $2 == "enabled" { found=1 } END { exit !found }' \
    "$results/weak-tls.sslscan.txt"
awk '$1 == "TLSv1.3" && $2 == "enabled" { found=1 } END { exit !found }' \
    "$results/modern-tls.sslscan.txt"
awk '$1 == "TLS" && $2 == "1" && $3 == "offered" { found=1 } END { exit !found }' \
    "$results/legacy-tls.testssl.txt"
awk '$1 == "TLS" && $2 == "1.2" && $3 == "offered" { found=1 } END { exit !found }' \
    "$results/weak-tls.testssl.txt"
awk '$1 == "TLS" && $2 == "1.3" && $3 == "offered" { found=1 } END { exit !found }' \
    "$results/modern-tls.testssl.txt"
awk '$1 == "Protocol" && $3 == "TLSv1" { found=1 } END { exit !found }' \
    "$results/legacy-tls.openssl.txt"
awk '$1 == "Protocol" && $3 == "TLSv1.2" { found=1 } END { exit !found }' \
    "$results/weak-tls.openssl.txt"
awk '($1 == "Protocol" && $3 == "TLSv1.3") || ($1 == "New," && $2 == "TLSv1.3,") { found=1 } END { exit !found }' \
    "$results/modern-tls.openssl.txt"

echo "Differential fixtures passed; artifacts: $results"
