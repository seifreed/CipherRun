#!/bin/bash
# Test script to verify Pin SHA256 calculation matches OpenSSL

echo "Testing Pin SHA256 calculation..."
echo ""

# Get SSL Labs' reported pin for badssl.com
echo "Expected Pin SHA256 from SSL Labs for badssl.com:"
echo "Pin SHA256: klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY="
echo ""

# Calculate pin using OpenSSL
echo "Calculating Pin SHA256 using OpenSSL..."
PIN_OPENSSL=$(echo | openssl s_client -connect badssl.com:443 -servername badssl.com 2>/dev/null | \
  openssl x509 -pubkey -noout 2>/dev/null | \
  openssl pkey -pubin -outform DER 2>/dev/null | \
  openssl dgst -sha256 -binary | \
  base64)

echo "OpenSSL Pin SHA256: $PIN_OPENSSL"
echo ""

# Note: We can't test CipherRun directly here because the project doesn't compile yet
# But we can verify the algorithm is correct by comparing with OpenSSL
echo "To test with CipherRun once compilation issues are fixed:"
echo "cargo test --lib test_pin_sha256_calculation -- --nocapture --ignored"
