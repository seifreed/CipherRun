#!/usr/bin/env bash
set -euo pipefail

generator_version="${OPENAPI_GENERATOR_VERSION:-7.8.0}"
output_dir="${1:-sdk/python}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spec="$root/target/cipherrun-openapi.json"
trap 'rm -f "$spec"' EXIT

(
    cd "$root"
    cargo run --quiet --locked --bin cipherrun-openapi > "$spec"
)

mkdir -p "$root/$output_dir"
docker run --rm \
    -v "$root:/local" \
    "openapitools/openapi-generator-cli:v${generator_version}" generate \
    -i /local/target/cipherrun-openapi.json \
    -g python \
    -o "/local/${output_dir}" \
    --package-name cipherrun_client \
    --additional-properties=packageVersion=0.4.0,projectName=cipherrun-client
