#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: scripts/sign-container.sh IMAGE_REF}"

if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is required to sign container images" >&2
    exit 1
fi

# Keyless signing uses the workflow OIDC identity in CI and the configured
# Sigstore identity locally; no long-lived signing key is accepted here.
cosign sign --yes "$image"
