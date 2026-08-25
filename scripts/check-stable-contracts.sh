#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
schema="${root}/docs/scan-results.schema.json"
openapi="${root}/target/cipherrun-openapi.json"

command -v jq >/dev/null 2>&1 || {
  echo "jq is required to validate stable contracts" >&2
  exit 1
}

jq -e '
  .properties.schema_version.type == "string" and
  .properties.scanner_version.type == "string" and
  .properties.ruleset_version.type == "string" and
  .properties.data_version.type == "string" and
  (.properties.vulnerabilities.items.properties.status.enum | index("confirmed_vulnerable")) != null and
  (.properties.vulnerabilities.items.properties.detection_method.enum | index("active_probe")) != null
' "${schema}" >/dev/null

cargo run --quiet --locked --bin cipherrun-openapi --features api > "${openapi}"
jq -e '
  (.openapi | type == "string" and startswith("3.")) and
  (.paths["/api/v1/scan"].post != null) and
  (.paths["/api/v1/stats"].get != null) and
  (.components.securitySchemes.api_key != null)
' "${openapi}" >/dev/null

echo "Stable CLI/JSON/OpenAPI contracts validated"
