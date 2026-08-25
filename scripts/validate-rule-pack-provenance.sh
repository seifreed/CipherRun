#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-${root}/target/rule-pack-manifest.json}"
mkdir -p "$(dirname "$output")"

command -v jq >/dev/null 2>&1 || {
  echo "jq is required to validate rule-pack provenance" >&2
  exit 1
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

yaml_value() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '
    /^rule_pack:/ { inside=1; next }
    inside && $1 == key ":" {
      value=$0
      sub(/^[^:]+:[[:space:]]*/, "", value)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
    inside && /^[^[:space:]]/ { exit }
  ' "$file"
}

yaml_source_value() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '
    /^  source:/ { inside=1; next }
    inside && $1 == key ":" {
      value=$0
      sub(/^[^:]+:[[:space:]]*/, "", value)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
    inside && /^  [^[:space:]]/ { exit }
  ' "$file"
}

tmp="${output}.tmp"
printf '{"schema_version":1,"packs":[' > "$tmp"
first=true
for file in "$root"/data/compliance/*.yaml; do
  [[ -f "$file" ]] || continue
  value="$(yaml_value "$file" version)"
  [[ -n "$value" ]] || {
    echo "Missing rule_pack.version metadata in ${file}" >&2
    exit 1
  }
  for key in organization document version publication_date url last_reviewed_at; do
    value="$(yaml_source_value "$file" "$key")"
    [[ -n "$value" ]] || {
      echo "Missing rule_pack.source.${key} metadata in ${file}" >&2
      exit 1
    }
  done
  version="$(yaml_value "$file" version)"
  organization="$(yaml_source_value "$file" organization)"
  document="$(yaml_source_value "$file" document)"
  source_version="$(yaml_source_value "$file" version)"
  publication_date="$(yaml_source_value "$file" publication_date)"
  url="$(yaml_source_value "$file" url)"
  reviewed="$(yaml_source_value "$file" last_reviewed_at)"
  digest="$(sha256_file "$file")"
  [[ "$first" == true ]] || printf ',' >> "$tmp"
  first=false
  jq -cn \
    --arg file "${file#"$root/"}" \
    --arg version "$version" \
    --arg organization "$organization" \
    --arg document "$document" \
    --arg source_version "$source_version" \
    --arg publication_date "$publication_date" \
    --arg url "$url" \
    --arg last_reviewed_at "$reviewed" \
    --arg sha256 "$digest" \
    '{file:$file,version:$version,source:{organization:$organization,document:$document,version:$source_version,publication_date:$publication_date,url:$url,last_reviewed_at:$last_reviewed_at},sha256:$sha256}' >> "$tmp"
done
printf ']}\n' >> "$tmp"
mv "$tmp" "$output"
echo "Rule-pack provenance manifest: $output"
