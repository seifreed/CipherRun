#!/usr/bin/env bash
set -euo pipefail

manifest="${1:-data/trust-stores-manifest.json}"
[[ -f "$manifest" ]] || {
  echo "Missing trust-store provenance manifest: $manifest" >&2
  exit 1
}

jq -e '.schema_version == 1 and (.stores | type == "object")' "$manifest" >/dev/null

while IFS=$'\t' read -r path expected_digest expected_count; do
  [[ "$path" == data/*.pem ]] || {
    echo "Manifest path is outside data/*.pem: $path" >&2
    exit 1
  }
  [[ -f "$path" ]] || {
    echo "Manifest references missing trust store: $path" >&2
    exit 1
  }

  actual_digest="$(shasum -a 256 "$path" | awk '{print $1}')"
  actual_count="$(grep -c 'BEGIN CERTIFICATE' "$path" || true)"
  [[ "$actual_digest" == "$expected_digest" ]] || {
    echo "Trust-store digest mismatch for $path" >&2
    exit 1
  }
  [[ "$actual_count" == "$expected_count" ]] || {
    echo "Trust-store certificate count mismatch for $path" >&2
    exit 1
  }
done < <(jq -r '.stores[] | [.path, .sha256, (.certificate_count | tostring)] | @tsv' "$manifest")

echo "Trust-store provenance validated: $manifest"
