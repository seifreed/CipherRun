#!/usr/bin/env bash
set -euo pipefail

manifest=${1:-docs/differential-fixtures.json}
results_dir=${2:-results/differential}

command -v jq >/dev/null || {
    echo "jq is required to validate differential evidence" >&2
    exit 1
}

jq -e '
    .version == "1" and
    (.fixtures | length == 58) and
    ([.fixtures[].name] as $names | ($names | length) == ($names | unique | length)) and
    all(.fixtures[];
        (.name | type == "string" and length > 0) and
        (.positive | type == "string" and length > 0) and
        (.negative | type == "string" and length > 0) and
        (.expected | type == "string" and length > 0) and
        (.false_positive_notes | type == "string" and length > 0) and
        (.false_negative_notes | type == "string" and length > 0) and
        (.safety | type == "string" and length > 0)
    )
' "$manifest" >/dev/null

missing=0
while IFS= read -r fixture; do
    transcript="$results_dir/$fixture.cipherrun.txt"
    result="$results_dir/$fixture.cipherrun.json"
    if [[ ! -s "$transcript" ]]; then
        echo "Missing captured transcript: $transcript" >&2
        missing=1
    fi
    if [[ ! -s "$result" ]]; then
        echo "Missing structured result: $result" >&2
        missing=1
    fi
done < <(jq -r '.fixtures[].name' "$manifest")

if (( missing != 0 )); then
    exit 1
fi

printf 'differential evidence: %s fixtures, transcripts and results present\n' \
    "$(jq '.fixtures | length' "$manifest")"
