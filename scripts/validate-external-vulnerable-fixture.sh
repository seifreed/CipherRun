#!/usr/bin/env bash
set -euo pipefail

image="docker.io/vulhub/openssl@sha256:3cf76769b6e33f45479e8bacd70d7c5c2bd8b8c4d5428ae3f613b1145a4a1c47"
patched_image="docker.io/vulhub/openssl@sha256:dffde83f29dc4a70e183ca7bf374f6a153839eda3a406fd5e2d41e953f72b978"
manifest="docs/external-vulnerable-fixtures.json"
name="cipherrun-external-openssl-1-0-1c"
patched_name="cipherrun-external-openssl-1-1-1m"
port="${OPENSSL_VULNERABLE_PORT:-14444}"
patched_port="${OPENSSL_PATCHED_PORT:-14451}"
output_dir="${CIPHERRUN_EXTERNAL_FIXTURE_OUTPUT_DIR:-results/external-fixture}"

command -v jq >/dev/null || {
    echo "jq is required to validate ${manifest}" >&2
    exit 1
}
jq -e --arg image "$image" --arg patched_image "$patched_image" \
    '.version == 1 and (.fixtures | length == 2) and
     .fixtures[0].name == "openssl-1-0-1c" and .fixtures[0].image == $image and
     .fixtures[1].name == "openssl-1-1-1m-patched" and .fixtures[1].image == $patched_image and
     all(.fixtures[]; (.expected | length > 0) and (.transcript | length > 0) and
       (.false_positive_notes | length > 0) and (.false_negative_notes | length > 0) and
       (.safety | length > 0))' "$manifest" >/dev/null
mkdir -p "$output_dir"

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker rm -f "$patched_name" >/dev/null 2>&1 || true
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

printf 'external vulnerable fixture: %s (%s)\n' "$version" "$image"
printf 'external patched control: %s (%s)\n' "$patched_version" "$patched_image"

echo | openssl s_client -connect "127.0.0.1:${port}" \
    -tls1 -cipher 'AES128-SHA:@SECLEVEL=0' -brief >"${output_dir}/openssl-1-0-1c-tls1.txt" 2>&1
echo | openssl s_client -connect "127.0.0.1:${patched_port}" \
    -tls1_2 -brief >"${output_dir}/openssl-1-1-1m-tls12.txt" 2>&1
cp "$manifest" "${output_dir}/fixture-metadata.json"
printf 'external fixture transcripts: %s\n' "$output_dir"
