#!/bin/bash
set -euo pipefail

profile=${1:?usage: fixture-server.sh legacy|legacy11|weak|modern|breach|sweet32|weak-ciphers}
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
    sweet32)
        exec python3 - <<'PY'
import socket

# Synthetic wire-level fixture: accept only the 3DES suite IDs probed by the
# SWEET32 detector, then return the smallest structurally valid ServerHello.
THREEDES = tuple(bytes.fromhex(value) for value in (
    "000a", "0016", "0013", "001b", "c012", "c008", "c00d", "c003",
    "c017", "008b", "001f", "0023",
))

ALERT = b"\x15\x03\x03\x00\x02\x02\x28"

def response(client_hello):
    if not any(cipher in client_hello for cipher in THREEDES):
        return ALERT
    body = b"\x03\x03" + (b"\x00" * 32) + b"\x00" + b"\x00\x0a" + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(3)
            try:
                client_hello = connection.recv(16384)
                connection.sendall(response(client_hello))
            except OSError:
                pass
PY
        ;;
    weak-ciphers)
        exec python3 - <<'PY'
import socket

# Synthetic wire-level fixture for legacy cipher detectors. It accepts only
# the registered RC4, NULL, RSA_EXPORT, and DH_EXPORT IDs; every other probe
# receives an alert. No certificate or application handshake is attempted.
WEAK = tuple(bytes.fromhex(value) for value in (
    # RC4
    "0005", "0004", "c011", "c007", "c00c", "c002", "c016", "0018",
    # NULL
    "0001", "0002", "003b", "c006", "c010", "c001", "c00b", "c015",
    # FREAK RSA_EXPORT
    "0003", "0006", "0008", "0062", "0064", "0060", "0061",
    # LOGJAM DH_EXPORT
    "0014", "0011", "0063", "0065",
))

ALERT = b"\x15\x03\x03\x00\x02\x02\x28"

def response(client_hello):
    if not any(cipher in client_hello for cipher in WEAK):
        return ALERT
    body = b"\x03\x03" + (b"\x00" * 32) + b"\x00" + b"\x00\x0a" + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(3)
            try:
                client_hello = connection.recv(16384)
                connection.sendall(response(client_hello))
            except OSError:
                pass
PY
        ;;
    *)
        echo "unknown fixture profile: $profile" >&2
        exit 2
        ;;
esac
