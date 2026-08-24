#!/usr/bin/env bash
set -euo pipefail

image="docker.io/vulhub/openssl@sha256:3cf76769b6e33f45479e8bacd70d7c5c2bd8b8c4d5428ae3f613b1145a4a1c47"
name="cipherrun-external-openssl-1-0-1c"
port="${OPENSSL_VULNERABLE_PORT:-14444}"

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull "$image" >/dev/null
version="$(docker run --rm --platform linux/amd64 "$image" openssl version)"
grep -q '^OpenSSL 1\.0\.1c ' <<<"$version" || {
    echo "Unexpected vulnerable fixture version: $version" >&2
    exit 1
}

docker run -d --name "$name" --platform linux/amd64 \
    -p "127.0.0.1:${port}:443" "$image" >/dev/null

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

printf 'external vulnerable fixture: %s (%s)\n' "$version" "$image"
