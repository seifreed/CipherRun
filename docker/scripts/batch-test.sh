#!/bin/bash
# Batch test multiple domains for TLS 1.3 support

DOMAINS=(
    "google.com"
    "youtube.com"
    "facebook.com"
    "twitter.com"
    "instagram.com"
    "linkedin.com"
    "reddit.com"
    "github.com"
    "stackoverflow.com"
    "wikipedia.org"
    "netflix.com"
    "amazon.com"
    "apple.com"
    "microsoft.com"
    "cloudflare.com"
    "isalud.com"
    "creand.es"
    "nsa.gov"
)

OUTPUT_FILE="${RESULTS_DIR:-/results}/batch_test_$(date +%Y%m%d_%H%M%S).csv"

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                   BATCH TLS 1.3 TESTING - ${#DOMAINS[@]} DOMAINS                         ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Testing ${#DOMAINS[@]} domains..."
echo "Results will be saved to: $OUTPUT_FILE"
echo ""

# CSV header
echo "Domain,OpenSSL_TLS13,CipherRun_TLS13_Ciphers,Status" > "$OUTPUT_FILE"

for domain in "${DOMAINS[@]}"; do
    echo -n "Testing $domain... "

    # Test with OpenSSL
    openssl_result=$(echo | timeout 3 openssl s_client -connect "$domain:443" -tls1_3 2>&1 | grep -q "^New, TLSv1.3" && echo "YES" || echo "NO")

    # Test with CipherRun
    cipherrun_result=$(timeout 60 cipherrun "$domain" 2>&1 | grep "TLS 1.3 -" | grep -oP '\d+(?= ciphers)' || echo "0")

    # Determine status
    if [ "$cipherrun_result" -gt 0 ]; then
        status="✓ WORKING"
        echo "✓"
    elif [ "$openssl_result" = "YES" ]; then
        status="✗ FAILED"
        echo "✗"
    else
        status="- NO TLS 1.3"
        echo "-"
    fi

    # Write to CSV
    echo "$domain,$openssl_result,$cipherrun_result,$status" >> "$OUTPUT_FILE"
done

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                            SUMMARY                                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Calculate statistics
total=$(grep -v "^Domain," "$OUTPUT_FILE" | wc -l)
working=$(grep "WORKING" "$OUTPUT_FILE" | wc -l)
failed=$(grep "FAILED" "$OUTPUT_FILE" | wc -l)
no_tls13=$(grep "NO TLS 1.3" "$OUTPUT_FILE" | wc -l)

success_rate=0
if [ $total -gt 0 ]; then
    success_rate=$((working * 100 / total))
fi

echo "Total Domains Tested: $total"
echo "Working:              $working (${success_rate}%)"
echo "Failed:               $failed"
echo "No TLS 1.3:           $no_tls13"
echo ""

echo "Working domains:"
grep "WORKING" "$OUTPUT_FILE" | cut -d',' -f1 | sed 's/^/  ✓ /'

if [ $failed -gt 0 ]; then
    echo ""
    echo "Failed domains:"
    grep "FAILED" "$OUTPUT_FILE" | cut -d',' -f1 | sed 's/^/  ✗ /'
fi

echo ""
echo "Full results saved to: $OUTPUT_FILE"
echo ""
