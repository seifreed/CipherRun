#!/usr/bin/env bash
set -euo pipefail

image="docker.io/vulhub/openssl@sha256:3cf76769b6e33f45479e8bacd70d7c5c2bd8b8c4d5428ae3f613b1145a4a1c47"
patched_image="docker.io/vulhub/openssl@sha256:dffde83f29dc4a70e183ca7bf374f6a153839eda3a406fd5e2d41e953f72b978"
manifest="docs/external-vulnerable-fixtures.json"
name="cipherrun-external-openssl-1-0-1c"
patched_name="cipherrun-external-openssl-1-1-1m"
poodle_name="cipherrun-external-openssl-1-0-1c-ssl3"
port="${OPENSSL_VULNERABLE_PORT:-14444}"
patched_port="${OPENSSL_PATCHED_PORT:-14451}"
poodle_port="${OPENSSL_POODLE_PORT:-14452}"
output_dir="${CIPHERRUN_EXTERNAL_FIXTURE_OUTPUT_DIR:-results/external-fixture}"
scanner_bin="${CIPHERRUN_BIN:-target/debug/cipherrun}"

command -v jq >/dev/null || {
    echo "jq is required to validate ${manifest}" >&2
    exit 1
}
jq -e --arg image "$image" --arg patched_image "$patched_image" \
    '.version == 1 and (.fixtures | length == 6) and
     .fixtures[0].name == "openssl-1-0-1c" and .fixtures[0].image == $image and
     .fixtures[1].name == "openssl-1-1-1m-patched" and .fixtures[1].image == $patched_image and
     .fixtures[2].name == "openssl-1-0-1c-ssl3-poodle" and .fixtures[2].image == $image and
     .fixtures[3].name == "openssl-1-1-1m-poodle-control" and .fixtures[3].image == $patched_image and
     .fixtures[4].name == "openssl-1-0-1c-padding" and .fixtures[4].image == $image and
     .fixtures[5].name == "openssl-1-1-1m-padding-control" and .fixtures[5].image == $patched_image and
     all(.fixtures[]; (.expected | length > 0) and (.transcript | length > 0) and
       (.false_positive_notes | length > 0) and (.false_negative_notes | length > 0) and
       (.safety | length > 0))' "$manifest" >/dev/null
mkdir -p "$output_dir"

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker rm -f "$patched_name" >/dev/null 2>&1 || true
    docker rm -f "$poodle_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull "$image" >/dev/null
docker pull "$patched_image" >/dev/null
version="$(docker run --rm --platform linux/amd64 "$image" openssl version)"
patched_version="$(docker run --rm --platform linux/amd64 "$patched_image" openssl version)"
grep -q '^OpenSSL 1\.0\.1c ' <<<"$version" || {
    echo "Unexpected vulnerable fixture version: $version" >&2
    exit 1
}
grep -q '^OpenSSL 1\.1\.1m ' <<<"$patched_version" || {
    echo "Unexpected patched fixture version: $patched_version" >&2
    exit 1
}

docker run -d --name "$name" --platform linux/amd64 \
    -p "127.0.0.1:${port}:443" "$image" >/dev/null
docker run -d --name "$patched_name" --platform linux/amd64 \
    -p "127.0.0.1:${patched_port}:443" "$patched_image" bash -ceu '
        mkdir -p /tmp/cipherrun-tls
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=patched.local \
            -keyout /tmp/cipherrun-tls/key.pem -out /tmp/cipherrun-tls/cert.pem >/dev/null 2>&1
        exec openssl s_server -quiet -www -accept 443 -tls1_2 \
            -cipher ECDHE-RSA-AES256-GCM-SHA384 \
            -cert /tmp/cipherrun-tls/cert.pem -key /tmp/cipherrun-tls/key.pem
    ' >/dev/null
docker run -d --name "$poodle_name" --platform linux/amd64 \
    -p "127.0.0.1:${poodle_port}:443" \
    "$image" sh -ceu '
        mkdir -p /tmp/cipherrun-tls
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ssl3.local \
            -keyout /tmp/cipherrun-tls/key.pem -out /tmp/cipherrun-tls/cert.pem >/dev/null 2>&1
        exec openssl s_server -quiet -www -accept 443 -cipher AES128-SHA \
            -cert /tmp/cipherrun-tls/cert.pem -key /tmp/cipherrun-tls/key.pem
    ' >/dev/null

for _ in {1..20}; do
    if echo | openssl s_client -connect "127.0.0.1:${port}" \
        -tls1 -cipher 'AES128-SHA:@SECLEVEL=0' -brief >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo | openssl s_client -connect "127.0.0.1:${port}" \
    -tls1 -cipher 'AES128-SHA:@SECLEVEL=0' -brief 2>&1 \
    | grep -q 'Protocol version: TLSv1'

patched_ready=0
for _ in {1..20}; do
    if echo | openssl s_client -connect "127.0.0.1:${patched_port}" \
        -tls1_2 -brief 2>&1 | grep -q 'Protocol version: TLSv1.2'; then
        patched_ready=1
        break
    fi
    sleep 1
done
test "$patched_ready" -eq 1

poodle_ready=0
for _ in {1..20}; do
    if docker exec "$poodle_name" sh -ceu \
        'echo | openssl s_client -connect 127.0.0.1:443 -ssl3 -cipher AES128-SHA 2>&1' \
        | grep -q 'Protocol  : SSLv3'; then
        poodle_ready=1
        break
    fi
    sleep 1
done
test "$poodle_ready" -eq 1

test -x "$scanner_bin"
"$scanner_bin" --allow-private --poodle --overwrite \
    --json "${output_dir}/openssl-1-0-1c-ssl3.cipherrun.json" \
    "127.0.0.1:${poodle_port}" \
    >"${output_dir}/openssl-1-0-1c-ssl3.cipherrun.txt" 2>&1
"$scanner_bin" --allow-private --poodle --overwrite \
    --json "${output_dir}/openssl-1-1-1m-poodle-control.cipherrun.json" \
    "127.0.0.1:${patched_port}" \
    >"${output_dir}/openssl-1-1-1m-poodle-control.cipherrun.txt" 2>&1
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-POODLE-001" and .status == "confirmed_vulnerable")' \
    "${output_dir}/openssl-1-0-1c-ssl3.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-POODLE-001" and .status == "not_vulnerable")' \
    "${output_dir}/openssl-1-1-1m-poodle-control.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-OPENSSL-ZERO-LENGTH-001" and .status == "inconclusive")' \
    "${output_dir}/openssl-1-0-1c-ssl3.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-OPENSSL-ZERO-LENGTH-001" and .status == "not_vulnerable")' \
    "${output_dir}/openssl-1-1-1m-poodle-control.cipherrun.json" >/dev/null
"$scanner_bin" --allow-private --vulnerable --overwrite \
    --json "${output_dir}/openssl-1-0-1c-padding.cipherrun.json" \
    "127.0.0.1:${poodle_port}" \
    >"${output_dir}/openssl-1-0-1c-padding.cipherrun.txt" 2>&1
"$scanner_bin" --allow-private --vulnerable --overwrite \
    --json "${output_dir}/openssl-1-1-1m-padding-control.cipherrun.json" \
    "127.0.0.1:${patched_port}" \
    >"${output_dir}/openssl-1-1-1m-padding-control.cipherrun.txt" 2>&1
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-PADDING-ORACLE-2016-001" and .status == "inconclusive")' \
    "${output_dir}/openssl-1-0-1c-padding.cipherrun.json" >/dev/null
jq -e '.vulnerabilities[] | select(.finding_id == "CR-TLS-PADDING-ORACLE-2016-001" and .status == "not_vulnerable")' \
    "${output_dir}/openssl-1-1-1m-padding-control.cipherrun.json" >/dev/null

printf 'external vulnerable fixture: %s (%s)\n' "$version" "$image"
printf 'external patched control: %s (%s)\n' "$patched_version" "$patched_image"

echo | openssl s_client -connect "127.0.0.1:${port}" \
    -tls1 -cipher 'AES128-SHA:@SECLEVEL=0' -brief >"${output_dir}/openssl-1-0-1c-tls1.txt" 2>&1
echo | openssl s_client -connect "127.0.0.1:${patched_port}" \
    -tls1_2 -brief >"${output_dir}/openssl-1-1-1m-tls12.txt" 2>&1
docker exec "$poodle_name" sh -ceu \
    'echo | openssl s_client -connect 127.0.0.1:443 -ssl3 -cipher AES128-SHA' \
    >"${output_dir}/openssl-1-0-1c-ssl3.txt" 2>&1
echo | openssl s_client -connect "127.0.0.1:${patched_port}" \
    -tls1_2 -brief >"${output_dir}/openssl-1-1-1m-poodle-control.txt" 2>&1
grep -q 'Protocol  : SSLv3' "${output_dir}/openssl-1-0-1c-ssl3.txt"
grep -q 'Cipher    : AES128-SHA' "${output_dir}/openssl-1-0-1c-ssl3.txt"
cp "$manifest" "${output_dir}/fixture-metadata.json"
printf 'external fixture transcripts: %s\n' "$output_dir"
