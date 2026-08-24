#!/usr/bin/env python3
"""Small, isolated STARTTLS negotiation fixtures for the differential lab."""

import socket
import sys
import threading


MODE = sys.argv[1] if len(sys.argv) == 2 else "positive"
if MODE not in {"positive", "negative"}:
    raise SystemExit("usage: starttls-fixture-server.py positive|negative")
POSITIVE = MODE == "positive"

PORTS = {
    "smtp": 2525,
    "imap": 2143,
    "pop3": 2110,
    "xmpp": 5222,
    "postgres": 55432,
    "mysql": 43306,
    "ldap": 3389,
}


def recv_some(client):
    try:
        return client.recv(4096)
    except OSError:
        return b""


def smtp(client):
    client.sendall(b"220 fixture ESMTP\r\n")
    recv_some(client)
    capability = b"250-fixture\r\n250-STARTTLS\r\n250 OK\r\n" if POSITIVE else b"250-fixture\r\n250 OK\r\n"
    client.sendall(capability)
    if POSITIVE:
        recv_some(client)
        client.sendall(b"220 Ready to start TLS\r\n")


def imap(client):
    client.sendall(b"* OK fixture IMAP4rev1 ready\r\n")
    recv_some(client)
    capability = (
        b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n"
        if POSITIVE
        else b"* CAPABILITY IMAP4rev1\r\na001 OK CAPABILITY completed\r\n"
    )
    client.sendall(capability)
    if POSITIVE:
        recv_some(client)
        client.sendall(b"a002 OK Begin TLS negotiation\r\n")


def pop3(client):
    client.sendall(b"+OK fixture POP3 ready\r\n")
    recv_some(client)
    capability = (
        b"+OK Capability list follows\r\nSTLS\r\n.\r\n"
        if POSITIVE
        else b"+OK Capability list follows\r\nTOP\r\n.\r\n"
    )
    client.sendall(capability)
    if POSITIVE:
        recv_some(client)
        client.sendall(b"+OK Begin TLS negotiation\r\n")


def xmpp(client):
    recv_some(client)
    features = (
        b"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>"
        if POSITIVE
        else b"<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/></stream:features>"
    )
    client.sendall(features)
    if POSITIVE:
        recv_some(client)
        client.sendall(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")


def postgres(client):
    request = client.recv(8)
    if len(request) == 8:
        client.sendall(b"S" if POSITIVE else b"N")


def mysql_packet(payload, sequence=0):
    length = len(payload)
    return bytes((length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, sequence)) + payload


def mysql(client):
    # Handshake v10 with CLIENT_SSL in the lower capability word when positive.
    handshake = bytearray(b"\x0a5.7-fixture\x00")
    handshake.extend(b"\x01\x00\x00\x00")
    handshake.extend(b"\x00" * 8)
    handshake.append(0)
    handshake.extend((0x0800 if POSITIVE else 0).to_bytes(2, "little"))
    client.sendall(mysql_packet(handshake))
    if POSITIVE:
        recv_some(client)


def ldap(client):
    recv_some(client)
    # LDAPMessage(messageID=1, ExtendedResponse(resultCode=success)).
    response = b"\x30\x0c\x02\x01\x01\x78\x07\x0a\x01" + (b"\x00" if POSITIVE else b"\x01") + b"\x04\x00\x04\x00"
    client.sendall(response)


HANDLERS = {
    "smtp": smtp,
    "imap": imap,
    "pop3": pop3,
    "xmpp": xmpp,
    "postgres": postgres,
    "mysql": mysql,
    "ldap": ldap,
}


def serve(protocol, listener):
    handler = HANDLERS[protocol]
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        with client:
            client.settimeout(5)
            try:
                handler(client)
            except (OSError, TimeoutError):
                pass


listeners = []
for protocol, port in PORTS.items():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(16)
    listeners.append(listener)
    threading.Thread(target=serve, args=(protocol, listener), daemon=True).start()

threading.Event().wait()
