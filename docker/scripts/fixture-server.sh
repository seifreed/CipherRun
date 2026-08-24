#!/bin/bash
set -euo pipefail

profile=${1:?usage: fixture-server.sh legacy|legacy11|weak|modern|breach}
workdir=/tmp/cipherrun-fixture
mkdir -p "$workdir"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
    -subj "/CN=${profile}-tls" \
    -keyout "$workdir/key.pem" -out "$workdir/cert.pem" >/dev/null 2>&1

case "$profile" in
    legacy)
        exec openssl s_server -quiet -www -accept 443 \
            -cert "$workdir/cert.pem" -key "$workdir/key.pem" \
            -tls1 -cipher 'AES128-SHA:@SECLEVEL=0'
        ;;
    legacy11)
        exec openssl s_server -quiet -www -accept 443 \
            -cert "$workdir/cert.pem" -key "$workdir/key.pem" \
            -tls1_1 -cipher 'AES128-SHA:@SECLEVEL=0'
        ;;
    weak)
        exec openssl s_server -quiet -www -accept 443 \
            -cert "$workdir/cert.pem" -key "$workdir/key.pem" \
            -tls1_2 -cipher 'AES128-SHA:@SECLEVEL=0'
        ;;
    modern)
        exec openssl s_server -quiet -www -accept 443 \
            -cert "$workdir/cert.pem" -key "$workdir/key.pem" -tls1_3
        ;;
    breach)
        exec python3 - "$workdir/cert.pem" "$workdir/key.pem" <<'PY'
import gzip
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

cert_file, key_file = sys.argv[1:]

class BreachHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        marker = parse_qs(urlsplit(self.path).query).get("test", [""])[0]
        body = (
            "<html><body>sessionid=test123; csrftoken=abc456 "
            f"reflection={marker}</body></html>"
        ).encode()
        # The fixture intentionally exposes the BREACH prerequisites. The
        # scanner reports potential exposure; it does not claim exploitation.
        compressed = gzip.compress(body)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(compressed)))
        self.send_header("Set-Cookie", "sessionid=test123")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

server = HTTPServer(("0.0.0.0", 443), BreachHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert_file, key_file)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
        ;;
    *)
        echo "unknown fixture profile: $profile" >&2
        exit 2
        ;;
esac
