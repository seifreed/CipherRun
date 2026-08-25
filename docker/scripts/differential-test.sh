#!/bin/bash
set -euo pipefail

results=${RESULTS_DIR:-/results}/differential
mkdir -p "$results"
cp /usr/share/cipherrun/differential-fixtures.json "$results/fixture-metadata.json"
jq -e '.version == "1" and (.fixtures | length == 58)' \
    "$results/fixture-metadata.json" >/dev/null

scan_fixture() {
    local target=$1
    local json="$results/$target.cipherrun.json"

    local exit_code=0
    cipherrun --allow-private --profile safe --overwrite --json "$json" "$target:443" \
        >"$results/$target.cipherrun.txt" 2>&1 || exit_code=$?
    # No differential probe supplies --baseline; code 4 is not actionable here.
    if (( exit_code > 1 && exit_code != 4 )); then
        echo "CipherRun failed for $target with exit code $exit_code" >&2
        return "$exit_code"
    fi
    sslscan --no-colour "$target:443" >"$results/$target.sslscan.txt" 2>&1 || true
    timeout 180 testssl.sh --protocols --warnings off --color 0 "$target:443" \
        >"$results/$target.testssl.txt" 2>&1 || true
    echo | openssl s_client -connect "$target:443" \
        >"$results/$target.openssl.txt" 2>&1 || true
}

scan_fixture legacy-tls
scan_fixture legacy11-tls
scan_fixture weak-tls
scan_fixture modern-tls

scan_breach_fixture() {
    local target=$1
    local artifact=$2
    local json="$results/$artifact.cipherrun.json"
    local exit_code=0
    cipherrun --allow-private --breach --overwrite --json "$json" "$target:443" \
        >"$results/$artifact.cipherrun.txt" 2>&1 || exit_code=$?
    if (( exit_code > 1 && exit_code != 4 )); then
        echo "CipherRun BREACH probe failed for $target with exit code $exit_code" >&2
        return "$exit_code"
    fi
}

scan_breach_fixture breach-tls breach-tls
scan_breach_fixture modern-tls modern-tls-breach

scan_interop_fixture() {
    local target=$1
    local json="$results/$target.cipherrun.json"
    local exit_code=0
    cipherrun --allow-private --profile safe --overwrite --json "$json" "$target:443" \
        >"$results/$target.cipherrun.txt" 2>&1 || exit_code=$?
    if (( exit_code > 1 && exit_code != 4 )); then
        echo "CipherRun failed for $target with exit code $exit_code" >&2
        return "$exit_code"
    fi
    sslscan --no-colour "$target:443" >"$results/$target.sslscan.txt" 2>&1 || true
    timeout 180 testssl.sh --protocols --warnings off --color 0 "$target:443" \
        >"$results/$target.testssl.txt" 2>&1 || true
    echo | openssl s_client -connect "$target:443" -servername interop.local \
        >"$results/$target.openssl.txt" 2>&1 || true
}

for target in nginx-interop apache-interop haproxy-interop envoy-interop caddy-interop; do
    scan_interop_fixture "$target"
done

scan_starttls_fixture() {
    local target=$1
    local protocol=$2
    local port=$3
    local artifact=$4
    local json="$results/$artifact.cipherrun.json"
    local exit_code=0
    cipherrun --allow-private --starttls "$protocol" --starttls-only \
        --overwrite --json "$json" "$target:$port" \
        >"$results/$artifact.cipherrun.txt" 2>&1 || exit_code=$?
    if (( exit_code > 1 && exit_code != 4 )); then
        echo "CipherRun STARTTLS probe failed for $target:$port with exit code $exit_code" >&2
        return "$exit_code"
    fi
    timeout 30 openssl s_client -starttls "$protocol" -connect "$target:$port" \
        -servername fixture.local -brief </dev/null \
        >"$results/$artifact.openssl.txt" 2>&1 || true
}

for fixture in \
    "smtp smtp 2525" "imap imap 2143" "pop3 pop3 2110" \
    "xmpp xmpp 5222" "postgres postgres 55432" "mysql mysql 43306" "ldap ldap 3389"; do
    read -r name protocol port <<<"$fixture"
    scan_starttls_fixture starttls-interop "$protocol" "$port" "${name}-starttls"
    scan_starttls_fixture starttls-negative "$protocol" "$port" "${name}-no-starttls"
done

scan_vulnerability_fixture() {
    local target=$1
    local artifact=$2
    local probe=$3
    local port=${4:-443}
    local json="$results/$artifact.cipherrun.json"
    local exit_code=0
    cipherrun --allow-private "$probe" --overwrite --json "$json" "$target:$port" \
        >"$results/$artifact.cipherrun.txt" 2>&1 || exit_code=$?
    if (( exit_code > 1 && exit_code != 4 )); then
        echo "CipherRun $probe probe failed for $target with exit code $exit_code" >&2
        return "$exit_code"
    fi
}

scan_vulnerability_fixture legacy-tls legacy-tls-beast --beast
scan_vulnerability_fixture modern-tls modern-tls-beast --beast
scan_vulnerability_fixture sweet32-tls sweet32 --sweet32
scan_vulnerability_fixture modern-tls modern-tls-sweet32 --sweet32
scan_vulnerability_fixture crime-tls crime --crime
scan_vulnerability_fixture crime-patched-tls crime-patched --crime
scan_vulnerability_fixture heartbleed-tls heartbleed --heartbleed
scan_vulnerability_fixture heartbleed-patched-tls heartbleed-patched --heartbleed
scan_vulnerability_fixture ccs-tls ccs --ccs
scan_vulnerability_fixture ccs-patched-tls ccs-patched --ccs
scan_vulnerability_fixture ticketbleed-tls ticketbleed --ticketbleed
scan_vulnerability_fixture ticketbleed-patched-tls ticketbleed-patched --ticketbleed
scan_vulnerability_fixture robot-tls robot --robot
scan_vulnerability_fixture robot-patched-tls robot-patched --robot
scan_vulnerability_fixture fallback-tls fallback --tls-fallback
scan_vulnerability_fixture fallback-patched-tls fallback-patched --tls-fallback
scan_vulnerability_fixture renegotiation-insecure-tls renegotiation-insecure --renegotiation 14456
scan_vulnerability_fixture renegotiation-secure-tls renegotiation-secure --renegotiation 14456
scan_vulnerability_fixture weak-ciphers-tls weak-ciphers --vulnerable
scan_vulnerability_fixture modern-tls modern-tls-weak-ciphers --vulnerable
scan_vulnerability_fixture poodle-tls poodle --poodle 14443
scan_vulnerability_fixture poodle-patched-tls poodle-patched --poodle 14443
scan_vulnerability_fixture poodle-variant-vulnerable-tls poodle-variant-vulnerable --poodle 14457
scan_vulnerability_fixture poodle-variant-patched-tls poodle-variant-patched --poodle 14457
scan_vulnerability_fixture grease-intolerant-tls grease-intolerant --grease 14453
scan_vulnerability_fixture grease-tolerant-tls grease-tolerant --grease 14453
scan_vulnerability_fixture early-data-tls early-data --early-data 14455
scan_vulnerability_fixture early-data-patched-tls early-data-patched --early-data 14455

scan_starttls_injection_fixture() {
    local target=$1
    local port=$2
    local artifact=$3
    local json="$results/$artifact.cipherrun.json"
    local exit_code=0
    cipherrun --allow-private --starttls-injection --overwrite --json "$json" \
        "$target:$port" >"$results/$artifact.cipherrun.txt" 2>&1 || exit_code=$?
    if (( exit_code > 1 && exit_code != 4 )); then
        echo "CipherRun STARTTLS injection probe failed for $target:$port with exit code $exit_code" >&2
        return "$exit_code"
    fi
}

for fixture in "smtp 25252" "imap 21432" "pop3 21110"; do
    read -r protocol port <<<"$fixture"
    scan_starttls_injection_fixture starttls-injection-tls "$port" "${protocol}-injection"
    scan_starttls_injection_fixture starttls-injection-patched-tls "$port" "${protocol}-injection-patched"
done

# Keep one deterministic evidence name per manifest fixture. Vulnerability
# probes use short artifact names internally; aliases make every published
# fixture expose the same JSON/transcript contract to the host validator.
alias_fixture_artifact() {
    local fixture=$1
    local artifact=$2
    cp "$results/$artifact.cipherrun.json" "$results/$fixture.cipherrun.json"
    cp "$results/$artifact.cipherrun.txt" "$results/$fixture.cipherrun.txt"
}

for alias in \
    "sweet32-tls sweet32" \
    "crime-tls crime" "crime-patched-tls crime-patched" \
    "heartbleed-tls heartbleed" "heartbleed-patched-tls heartbleed-patched" \
    "ccs-tls ccs" "ccs-patched-tls ccs-patched" \
    "ticketbleed-tls ticketbleed" "ticketbleed-patched-tls ticketbleed-patched" \
    "robot-tls robot" "robot-patched-tls robot-patched" \
    "fallback-tls fallback" "fallback-patched-tls fallback-patched" \
    "renegotiation-insecure-tls renegotiation-insecure" \
    "renegotiation-secure-tls renegotiation-secure" \
    "weak-ciphers-tls weak-ciphers" \
    "poodle-tls poodle" "poodle-patched-tls poodle-patched" \
    "poodle-variant-vulnerable-tls poodle-variant-vulnerable" \
    "poodle-variant-patched-tls poodle-variant-patched" \
    "grease-intolerant-tls grease-intolerant" \
    "grease-tolerant-tls grease-tolerant" \
    "early-data-tls early-data" "early-data-patched-tls early-data-patched"; do
    read -r fixture artifact <<<"$alias"
    alias_fixture_artifact "$fixture" "$artifact"
done

# Some probes intentionally emit only JSON. Keep a truthful transcript artifact
# so the evidence validator can distinguish "no text emitted" from "not run".
for transcript in "$results"/*.cipherrun.txt; do
    if [[ ! -s "$transcript" ]]; then
        printf 'CipherRun emitted no textual output; see the structured JSON artifact.\n' \
            >"$transcript"
    fi
done

jq -e '.protocols[] | select(.protocol == "TLS10" and .supported == true)' \
    "$results/legacy-tls.cipherrun.json" >/dev/null
jq -e 'all(.protocols[]; .protocol != "TLS12" or .supported == false)' \
    "$results/legacy-tls.cipherrun.json" >/dev/null
jq -e '.protocols[] | select(.protocol == "TLS11" and .supported == true)' \
    "$results/legacy11-tls.cipherrun.json" >/dev/null
jq -e 'all(.protocols[]; .protocol != "TLS12" or .supported == false)' \
    "$results/legacy11-tls.cipherrun.json" >/dev/null
jq -e '.protocols[] | select(.protocol == "TLS12" and .supported == true)' \
    "$results/weak-tls.cipherrun.json" >/dev/null
jq -e 'all(.protocols[]; .protocol != "TLS13" or .supported == false)' \
    "$results/weak-tls.cipherrun.json" >/dev/null
jq -e '.protocols[] | select(.protocol == "TLS13" and .supported == true)' \
    "$results/modern-tls.cipherrun.json" >/dev/null
jq -e 'all(.protocols[]; .protocol != "TLS12" or .supported == false)' \
    "$results/modern-tls.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-BREACH-001" and .status == "potential_exposure")' \
    "$results/breach-tls.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-BREACH-001" and .status == "not_vulnerable")' \
    "$results/modern-tls-breach.cipherrun.json" >/dev/null

for target in nginx-interop apache-interop haproxy-interop envoy-interop caddy-interop; do
    jq -e '.protocols[] | select(.protocol == "TLS13" and .supported == true)' \
        "$results/$target.cipherrun.json" >/dev/null
    jq -e 'all(.protocols[]; .protocol != "TLS10" and .protocol != "TLS11" or .supported == false)' \
        "$results/$target.cipherrun.json" >/dev/null
    awk '$1 == "TLSv1.2" && $2 == "enabled" { found=1 } END { exit !found }' \
        "$results/$target.sslscan.txt"
    awk '$1 == "TLSv1.3" && $2 == "enabled" { found=1 } END { exit !found }' \
        "$results/$target.sslscan.txt"
    awk '$1 == "TLSv1.0" && $2 == "disabled" { found=1 } END { exit !found }' \
        "$results/$target.sslscan.txt"
    awk '$1 == "TLSv1.1" && $2 == "disabled" { found=1 } END { exit !found }' \
        "$results/$target.sslscan.txt"
    awk '$1 == "TLS" && $2 == "1.2" && $3 == "offered" { found=1 } END { exit !found }' \
        "$results/$target.testssl.txt"
    awk '$1 == "TLS" && $2 == "1.3" && $3 == "offered" { found=1 } END { exit !found }' \
        "$results/$target.testssl.txt"
    awk '$1 == "TLS" && $2 == "1" && $3 == "not" { found=1 } END { exit !found }' \
        "$results/$target.testssl.txt"
    awk '$1 == "TLS" && $2 == "1.1" && $3 == "not" { found=1 } END { exit !found }' \
        "$results/$target.testssl.txt"
done
for fixture in smtp imap pop3 xmpp postgres mysql ldap; do
    jq -e '.starttls_supported == true' \
        "$results/${fixture}-starttls.cipherrun.json" >/dev/null
    jq -e '.starttls_supported == false' \
        "$results/${fixture}-no-starttls.cipherrun.json" >/dev/null
done
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-BEAST-001" and .status == "confirmed_vulnerable")' \
    "$results/legacy-tls-beast.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-BEAST-001" and .status == "not_vulnerable")' \
    "$results/modern-tls-beast.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-SWEET32-001" and .status == "confirmed_vulnerable")' \
    "$results/sweet32.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-SWEET32-001" and .status == "not_vulnerable")' \
    "$results/modern-tls-sweet32.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-CRIME-001" and .status == "confirmed_vulnerable")' \
    "$results/crime.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-CRIME-001" and .status == "not_vulnerable")' \
    "$results/crime-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-HEARTBLEED-001" and .status == "confirmed_vulnerable")' \
    "$results/heartbleed.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-HEARTBLEED-001" and .status == "not_vulnerable")' \
    "$results/heartbleed-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-CCS-INJECTION-001" and .status == "confirmed_vulnerable")' \
    "$results/ccs.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-CCS-INJECTION-001" and .status == "not_vulnerable")' \
    "$results/ccs-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-TICKETBLEED-001" and .status == "confirmed_vulnerable")' \
    "$results/ticketbleed.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-TICKETBLEED-001" and .status == "not_vulnerable")' \
    "$results/ticketbleed-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-ROBOT-001" and .status == "confirmed_vulnerable")' \
    "$results/robot.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-ROBOT-001" and .status == "not_vulnerable")' \
    "$results/robot-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-FALLBACK-SCSV-001" and .status == "confirmed_vulnerable")' \
    "$results/fallback.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-FALLBACK-SCSV-001" and .status == "not_vulnerable")' \
    "$results/fallback-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-RENEGOTIATION-001" and .status == "inconclusive")' \
    "$results/renegotiation-insecure.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-RENEGOTIATION-001" and .status == "not_vulnerable")' \
    "$results/renegotiation-secure.cipherrun.json" >/dev/null
for fixture in smtp imap pop3; do
    jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-STARTTLS-INJECTION-001" and .status == "confirmed_vulnerable")' \
        "$results/${fixture}-injection.cipherrun.json" >/dev/null
    jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-STARTTLS-INJECTION-001" and .status == "not_vulnerable")' \
        "$results/${fixture}-injection-patched.cipherrun.json" >/dev/null
done
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-POODLE-001" and .status == "confirmed_vulnerable")' \
    "$results/poodle.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-POODLE-001" and .status == "not_vulnerable")' \
    "$results/poodle-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-ZOMBIE-POODLE-001" and .status == "confirmed_vulnerable")' \
    "$results/poodle-variant-vulnerable.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-GOLDEN-DOODLE-001" and .status == "confirmed_vulnerable")' \
    "$results/poodle-variant-vulnerable.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select((.finding_id == "CR-TLS-ZOMBIE-POODLE-001" or .finding_id == "CR-TLS-GOLDEN-DOODLE-001") and .status == "not_vulnerable")' \
    "$results/poodle-variant-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-GREASE-INTOLERANCE-001" and (.evidence.observed | contains("rejected")))' \
    "$results/grease-intolerant.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-GREASE-INTOLERANCE-001" and (.evidence.observed | contains("tolerates")))' \
    "$results/grease-tolerant.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-EARLY-DATA-REPLAY-001" and .status == "confirmed_vulnerable")' \
    "$results/early-data.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-EARLY-DATA-REPLAY-001" and .status == "not_vulnerable")' \
    "$results/early-data-patched.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-RC4-001" and .status == "confirmed_vulnerable")' \
    "$results/weak-ciphers.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-NULL-CIPHER-001" and .status == "confirmed_vulnerable")' \
    "$results/weak-ciphers.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-FREAK-001" and .status == "confirmed_vulnerable")' \
    "$results/weak-ciphers.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-LOGJAM-001" and .status == "confirmed_vulnerable")' \
    "$results/weak-ciphers.cipherrun.json" >/dev/null
jq -e 'all(.vulnerabilities[]; ((.finding_id == "CR-TLS-RC4-001" or .finding_id == "CR-TLS-NULL-CIPHER-001" or .finding_id == "CR-TLS-FREAK-001" or .finding_id == "CR-TLS-LOGJAM-001") | not) or (.status != "confirmed_vulnerable"))' \
    "$results/modern-tls-weak-ciphers.cipherrun.json" >/dev/null

awk '$1 == "TLSv1.0" && $2 == "enabled" { found=1 } END { exit !found }' \
    "$results/legacy-tls.sslscan.txt"
awk '$1 == "TLSv1.1" && $2 == "enabled" { found=1 } END { exit !found }' \
    "$results/legacy11-tls.sslscan.txt"
awk '$1 == "TLSv1.2" && $2 == "enabled" { found=1 } END { exit !found }' \
    "$results/weak-tls.sslscan.txt"
awk '$1 == "TLSv1.3" && $2 == "enabled" { found=1 } END { exit !found }' \
    "$results/modern-tls.sslscan.txt"
awk '$1 == "TLS" && $2 == "1" && $3 == "offered" { found=1 } END { exit !found }' \
    "$results/legacy-tls.testssl.txt"
awk '$1 == "TLS" && $2 == "1.1" && $3 == "offered" { found=1 } END { exit !found }' \
    "$results/legacy11-tls.testssl.txt"
awk '$1 == "TLS" && $2 == "1.2" && $3 == "offered" { found=1 } END { exit !found }' \
    "$results/weak-tls.testssl.txt"
awk '$1 == "TLS" && $2 == "1.3" && $3 == "offered" { found=1 } END { exit !found }' \
    "$results/modern-tls.testssl.txt"
awk '$1 == "Protocol" && $3 == "TLSv1" { found=1 } END { exit !found }' \
    "$results/legacy-tls.openssl.txt"
awk '$1 == "Protocol" && $3 == "TLSv1.1" { found=1 } END { exit !found }' \
    "$results/legacy11-tls.openssl.txt"
awk '$1 == "Protocol" && $3 == "TLSv1.2" { found=1 } END { exit !found }' \
    "$results/weak-tls.openssl.txt"
awk '($1 == "Protocol" && $3 == "TLSv1.3") || ($1 == "New," && $2 == "TLSv1.3,") { found=1 } END { exit !found }' \
    "$results/modern-tls.openssl.txt"

echo "Differential fixtures passed; artifacts: $results"
