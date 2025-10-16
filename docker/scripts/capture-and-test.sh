#!/bin/bash
# Capture network traffic while running CipherRun

set -e

DOMAIN=$1
OUTPUT_DIR=${PCAP_DIR:-/captures}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="${OUTPUT_DIR}/${DOMAIN}_${TIMESTAMP}.pcap"
SCAN_OUTPUT="${RESULTS_DIR:-/results}/${DOMAIN}_${TIMESTAMP}.txt"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    echo ""
    echo "Example: $0 creand.es"
    echo ""
    echo "This will:"
    echo "  1. Start packet capture with tcpdump"
    echo "  2. Run CipherRun scan"
    echo "  3. Stop capture and save pcap file"
    echo "  4. Show basic analysis"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║              CAPTURE AND TEST - Network Analysis Tool                     ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Target:      $DOMAIN"
echo "PCAP File:   $PCAP_FILE"
echo "Scan Output: $SCAN_OUTPUT"
echo ""

# Start tcpdump in background
echo "[*] Starting packet capture..."
tcpdump -i any -w "$PCAP_FILE" "host $DOMAIN or host $(dig +short $DOMAIN | head -1)" &
TCPDUMP_PID=$!

# Wait for tcpdump to initialize
sleep 2

# Run CipherRun
echo "[*] Running CipherRun scan..."
cipherrun "$DOMAIN" > "$SCAN_OUTPUT" 2>&1

# Wait a bit to capture final packets
sleep 2

# Stop tcpdump
echo "[*] Stopping packet capture..."
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                            RESULTS                                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Show TLS 1.3 results
echo "=== CipherRun TLS Detection ==="
grep -E "(TLS 1\.[23] -|Protocol Support)" "$SCAN_OUTPUT" || true
echo ""

# Basic pcap analysis
echo "=== Packet Capture Summary ==="
echo "Total packets captured:"
tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l
echo ""
echo "TLS ClientHello packets:"
tcpdump -r "$PCAP_FILE" 'tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16' 2>/dev/null | grep -c "length" || echo "0"
echo ""

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                        ANALYSIS COMMANDS                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "View PCAP with tshark:"
echo "  tshark -r $PCAP_FILE"
echo ""
echo "Filter TLS handshakes:"
echo "  tshark -r $PCAP_FILE -Y 'tls.handshake.type == 1'"
echo ""
echo "Extract ClientHello hex:"
echo "  tshark -r $PCAP_FILE -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_length -e tls.handshake.extension.type"
echo ""
echo "View scan results:"
echo "  cat $SCAN_OUTPUT"
echo ""
