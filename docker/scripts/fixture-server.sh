#!/bin/bash
set -euo pipefail

profile=${1:?usage: fixture-server.sh legacy|legacy11|weak|modern|breach|sweet32|crime|crime-patched|heartbleed|heartbleed-patched|ccs|ccs-patched|ticketbleed|ticketbleed-patched|robot|robot-patched|weak-ciphers}
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
    crime|crime-patched)
        exec python3 - "${profile}" <<'PY'
import socket
import sys

compression = 0x01 if sys.argv[1] == "crime" else 0x00

def response():
    body = b"\x03\x03" + (b"\x00" * 32) + b"\x00" + b"\x00\x2f" + bytes([compression]) + b"\x00\x00"
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
                connection.recv(16384)
                connection.sendall(response())
            except (OSError, TimeoutError):
                pass
PY
        ;;
    heartbleed|heartbleed-patched)
        exec python3 - "${profile}" <<'PY'
import socket
import sys

vulnerable = sys.argv[1] == "heartbleed"

def server_hello():
    body = b"\x03\x03" + (b"\xaa" * 32) + b"\x00" + b"\x13\x01" + b"\x00"
    if vulnerable:
        body += b"\x00\x05\x00\x0f\x00\x01\x01"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

def heartbeat_response():
    payload = b"\x00" * 253
    body = b"\x02" + len(payload).to_bytes(2, "big") + payload
    return b"\x18\x03\x03" + len(body).to_bytes(2, "big") + body

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(3)
            try:
                connection.recv(16384)
                connection.sendall(server_hello())
                if vulnerable:
                    connection.recv(16384)
                    connection.sendall(heartbeat_response())
            except (OSError, TimeoutError):
                pass
PY
        ;;
    ccs|ccs-patched)
        exec python3 - "${profile}" <<'PY'
import socket
import sys

vulnerable = sys.argv[1] == "ccs"

def server_hello():
    body = b"\x03\x01" + (b"\xaa" * 32) + b"\x00" + b"\x00\x2f" + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(3)
            try:
                connection.recv(16384)
                connection.sendall(server_hello())
                connection.recv(16384)
                response = b"\x14\x03\x01\x00\x01\x01" if vulnerable else b"\x15\x03\x01\x00\x02\x02\x28"
                connection.sendall(response)
            except (OSError, TimeoutError):
                pass
PY
        ;;
    ticketbleed|ticketbleed-patched)
        exec python3 - "${profile}" <<'PY'
import socket
import sys

vulnerable = sys.argv[1] == "ticketbleed"
marker = bytes.fromhex("cafebabedeadbeef0123456789abcdef")

def handshake_record(message):
    return b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message

def new_session_ticket():
    body = b"\x00\x00\x00\x00" + b"\x00\x06ticket"
    message = b"\x04" + len(body).to_bytes(3, "big") + body
    return handshake_record(message)

def server_hello():
    session_id = marker + (b"\x77" * 16 if vulnerable else b"")
    body = b"\x03\x03" + (b"\x00" * 32) + bytes([len(session_id)]) + session_id + b"\xc0\x2f\x00"
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    return handshake_record(message)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(3)
            try:
                connection.recv(16384)
                connection.sendall(new_session_ticket())
                connection.recv(16384)
                connection.sendall(server_hello())
            except (OSError, TimeoutError):
                pass
PY
        ;;
    robot|robot-patched)
        openssl x509 -in "$workdir/cert.pem" -outform DER -out "$workdir/cert.der"
        exec python3 - "$workdir/cert.der" "${profile}" <<'PY'
import socket
import sys

cert = open(sys.argv[1], "rb").read()
vulnerable = sys.argv[2] == "robot"

def handshake(kind, body=b""):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body

def handshake_record(messages):
    payload = b"".join(messages)
    return b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload

def server_messages():
    hello_body = b"\x03\x01" + (b"\xaa" * 32) + b"\x00\x00\x2f\x00"
    cert_body = (3 + len(cert)).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert
    return handshake_record((handshake(0x02, hello_body), handshake(0x0b, cert_body), handshake(0x0e)))

def alert_code(client_data):
    if not vulnerable:
        return 0x46
    payload = client_data[12:]
    if payload and payload[0] == 0xff:
        return 0x47
    if payload[:2] == b"\x00\x01":
        return 0x48
    if payload and payload[0] == 0xaa:
        return 0x49
    return 0x46

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen()
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(4)
            try:
                connection.recv(16384)
                connection.sendall(server_messages())
                client_data = connection.recv(16384)
                code = alert_code(client_data)
                connection.sendall(bytes.fromhex(f"150303000202{code:02x}"))
            except (OSError, TimeoutError):
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
