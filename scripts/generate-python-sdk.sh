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

# OpenAPI Generator escapes Markdown entities inside setup.py's long string;
# raw-string syntax keeps generated clients warning-free under modern Python.
python3 - "$root/$output_dir/setup.py" "$root/$output_dir" <<'PY'
from pathlib import Path
import sys

setup_path, output_dir = map(Path, sys.argv[1:])
setup_text = setup_path.read_text()
setup_path.write_text(
    setup_text.replace('long_description="""\\', 'long_description=r"""\\', 1)
)

# Generated model dictionaries can contain datetime/date values.
for model_path in (output_dir / "cipherrun_client" / "models").glob("*.py"):
    model_text = model_path.read_text()
    model_path.write_text(
        model_text.replace(
            "json.dumps(self.to_dict())", "json.dumps(self.to_dict(), default=str)"
        )
    )
PY
