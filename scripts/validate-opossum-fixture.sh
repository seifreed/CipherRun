#!/usr/bin/env bash
set -euo pipefail

vulnerable_image="docker.io/vulhub/openssl@sha256:dffde83f29dc4a70e183ca7bf374f6a153839eda3a406fd5e2d41e953f72b978"
patched_image="${OPOSSUM_PATCHED_IMAGE:-cipherrun-lab:0.4.0}"
fixture="fixtures/opossum/crafted.crt.b64"
output_dir="${OPOSSUM_FIXTURE_OUTPUT_DIR:-results/opossum-fixture}"
certificate="$(mktemp)"
trap 'rm -f "$certificate"' EXIT
mkdir -p "$output_dir"

base64 --decode "$fixture" >"$certificate"
test "$(shasum -a 256 "$certificate" | awk '{print $1}')" = \
    "ba2b227b073dbd61c2d9547e81955d310520d9b5891f4b3feb136e9674c8551f"

docker pull "$vulnerable_image" >/dev/null
docker image inspect "$patched_image" >/dev/null
docker run --rm --platform linux/amd64 "$vulnerable_image" openssl version \
    >"$output_dir/openssl-vulnerable.version.txt"
docker run --rm "$patched_image" openssl version \
    >"$output_dir/openssl-patched.version.txt"

set +e
docker run --rm --platform linux/amd64 \
    -v "$certificate:/tmp/crafted.crt:ro" "$vulnerable_image" \
    sh -ceu 'timeout 3 openssl x509 -inform DER -in /tmp/crafted.crt -noout -text' \
    >"$output_dir/openssl-vulnerable.parse.txt" 2>&1
vulnerable_rc=$?
docker run --rm \
    -v "$certificate:/tmp/crafted.crt:ro" "$patched_image" \
    sh -ceu 'timeout 3 openssl x509 -inform DER -in /tmp/crafted.crt -noout -text' \
    >"$output_dir/openssl-patched.parse.txt" 2>&1
patched_rc=$?
set -e

test "$vulnerable_rc" -eq 124
test "$patched_rc" -eq 0
cat >"$output_dir/fixture-metadata.json" <<EOF
{
  "version": 1,
  "certificate_sha256": "ba2b227b073dbd61c2d9547e81955d310520d9b5891f4b3feb136e9674c8551f",
  "source_url": "https://github.com/jkakavas/CVE-2022-0778-POC/blob/main/crafted.crt",
  "vulnerable_image": "$vulnerable_image",
  "patched_image": "$patched_image",
  "expected": "OpenSSL vulnerable parser times out; patched parser returns",
  "safety": "isolated-local-parser-timeout",
  "limitation": "This validates a local OpenSSL parser boundary. CipherRun's remote Opossum probe remains inconclusive by design."
}
EOF
printf 'Opossum parser fixture passed: vulnerable_rc=%s patched_rc=%s\n' "$vulnerable_rc" "$patched_rc"
