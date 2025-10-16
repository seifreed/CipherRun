#!/bin/bash
# Compare ClientHello from OpenSSL vs CipherRun

set -e

DOMAIN=$1
OUTPUT_DIR=${PCAP_DIR:-/captures}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    echo ""
    echo "Example: $0 creand.es"
    echo ""
    echo "This will capture and compare ClientHello packets from:"
    echo "  1. OpenSSL s_client (working)"
    echo "  2. CipherRun (may fail on strict servers)"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║              CLIENTHELLO COMPARISON - OpenSSL vs CipherRun                ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Target: $DOMAIN"
echo ""

# Capture OpenSSL ClientHello
echo "[1/4] Capturing OpenSSL ClientHello..."
OPENSSL_PCAP="${OUTPUT_DIR}/openssl_${DOMAIN}_${TIMESTAMP}.pcap"
tcpdump -i any -w "$OPENSSL_PCAP" "host $DOMAIN" &
TCPDUMP_PID=$!
sleep 1

echo | timeout 5 openssl s_client -connect "$DOMAIN:443" -tls1_3 >/dev/null 2>&1 || true
sleep 1

kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

# Capture CipherRun ClientHello
echo "[2/4] Capturing CipherRun ClientHello..."
CIPHERRUN_PCAP="${OUTPUT_DIR}/cipherrun_${DOMAIN}_${TIMESTAMP}.pcap"
tcpdump -i any -w "$CIPHERRUN_PCAP" "host $DOMAIN" &
TCPDUMP_PID=$!
sleep 1

timeout 30 cipherrun "$DOMAIN" >/dev/null 2>&1 || true
sleep 1

kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

# Extract and compare ClientHellos
echo "[3/4] Extracting ClientHello packets..."

echo ""
echo "=== OpenSSL ClientHello ==="
tshark -r "$OPENSSL_PCAP" -Y 'tls.handshake.type == 1' -V 2>/dev/null | grep -A 100 "Secure Sockets Layer" | head -80 || echo "No ClientHello found"

echo ""
echo "=== CipherRun ClientHello ==="
tshark -r "$CIPHERRUN_PCAP" -Y 'tls.handshake.type == 1' -V 2>/dev/null | grep -A 100 "Secure Sockets Layer" | head -80 || echo "No ClientHello found"

echo ""
echo "[4/4] Extension comparison..."

echo ""
echo "=== OpenSSL Extensions ==="
tshark -r "$OPENSSL_PCAP" -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extension.type 2>/dev/null | tr '\t' '\n' | sort -u | while read ext; do
    case "$ext" in
        "0") echo "  0x0000 - server_name (SNI)" ;;
        "10") echo "  0x000a - supported_groups" ;;
        "11") echo "  0x000b - ec_point_formats" ;;
        "13") echo "  0x000d - signature_algorithms" ;;
        "16") echo "  0x0010 - application_layer_protocol_negotiation" ;;
        "23") echo "  0x0017 - extended_master_secret" ;;
        "43") echo "  0x002b - supported_versions" ;;
        "45") echo "  0x002d - psk_key_exchange_modes" ;;
        "51") echo "  0x0033 - key_share" ;;
        "80") echo "  0x0050 - signature_algorithms_cert" ;;
        "65281") echo "  0xff01 - renegotiation_info" ;;
        *) echo "  $ext - unknown" ;;
    esac
done

echo ""
echo "=== CipherRun Extensions ==="
tshark -r "$CIPHERRUN_PCAP" -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extension.type 2>/dev/null | tr '\t' '\n' | sort -u | while read ext; do
    case "$ext" in
        "0") echo "  0x0000 - server_name (SNI)" ;;
        "10") echo "  0x000a - supported_groups" ;;
        "11") echo "  0x000b - ec_point_formats" ;;
        "13") echo "  0x000d - signature_algorithms" ;;
        "16") echo "  0x0010 - application_layer_protocol_negotiation" ;;
        "23") echo "  0x0017 - extended_master_secret" ;;
        "43") echo "  0x002b - supported_versions" ;;
        "45") echo "  0x002d - psk_key_exchange_modes" ;;
        "51") echo "  0x0033 - key_share" ;;
        "80") echo "  0x0050 - signature_algorithms_cert" ;;
        "65281") echo "  0xff01 - renegotiation_info" ;;
        *) echo "  $ext - unknown" ;;
    esac
done

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                            FILES SAVED                                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "OpenSSL PCAP:   $OPENSSL_PCAP"
echo "CipherRun PCAP: $CIPHERRUN_PCAP"
echo ""
echo "To analyze further:"
echo "  wireshark $OPENSSL_PCAP"
echo "  wireshark $CIPHERRUN_PCAP"
echo ""
