#!/bin/bash
set -euo pipefail

profile=${1:?usage: fixture-server.sh weak|modern}
workdir=/tmp/cipherrun-fixture
mkdir -p "$workdir"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
    -subj "/CN=${profile}-tls" \
    -keyout "$workdir/key.pem" -out "$workdir/cert.pem" >/dev/null 2>&1

case "$profile" in
    weak)
        exec openssl s_server -quiet -www -accept 443 \
            -cert "$workdir/cert.pem" -key "$workdir/key.pem" \
            -tls1_2 -cipher 'AES128-SHA:@SECLEVEL=0'
        ;;
    modern)
        exec openssl s_server -quiet -www -accept 443 \
            -cert "$workdir/cert.pem" -key "$workdir/key.pem" -tls1_3
        ;;
    *)
        echo "unknown fixture profile: $profile" >&2
        exit 2
        ;;
esac
