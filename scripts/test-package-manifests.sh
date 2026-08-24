#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
dist="$root/dist"
out="$root/out"
mkdir -p "$dist"
for archive in \
    cipherrun-v0.4.0-x86_64-apple-darwin.tar.gz \
    cipherrun-v0.4.0-aarch64-apple-darwin.tar.gz \
    cipherrun-v0.4.0-x86_64-pc-windows-msvc.zip \
    cipherrun-v0.4.0-aarch64-pc-windows-msvc.zip; do
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  %s\n' "$archive" \
        >"${dist}/${archive}.sha256"
done

scripts/generate-package-manifests.sh 0.4.0 "$dist" "$out"
test -s "$out/cipherrun.rb"
test -s "$out/cipherrun.json"
grep -q '0123456789abcdef' "$out/cipherrun.rb"
grep -q 'x86_64-pc-windows-msvc.zip' "$out/cipherrun.json"
echo "Package manifest contract passed"
