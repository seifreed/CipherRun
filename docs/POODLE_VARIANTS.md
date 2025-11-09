# POODLE Vulnerability Variants Detection

## Overview

CipherRun implements detection for 6 different POODLE (Padding Oracle On Downgraded Legacy Encryption) vulnerability variants. This document provides technical details about each variant, detection methodology, and mitigation strategies.

## Implemented Variants

### 1. Classic POODLE (SSLv3) - CVE-2014-3566

**Description**: The original POODLE attack exploits a flaw in SSL 3.0's CBC mode padding validation. An attacker can decrypt HTTPS traffic by observing server responses to manipulated padding.

**Affected Systems**:
- Servers supporting SSL 3.0 protocol
- All CBC cipher suites in SSL 3.0

**Detection Method**:
- Simple protocol support check
- Attempts SSL 3.0 handshake
- Reports vulnerable if SSL 3.0 is enabled

**Severity**: HIGH

**Mitigation**:
- Disable SSL 3.0 protocol entirely
- Configure server to only accept TLS 1.2 or higher
- Use TLS_FALLBACK_SCSV to prevent downgrade attacks

### 2. TLS POODLE - CVE-2014-8730

**Description**: Some TLS implementations (primarily TLS 1.0-1.2) contain the same CBC padding validation flaw as SSL 3.0, making them vulnerable to POODLE-style attacks even without SSL 3.0.

**Affected Systems**:
- F5 devices
- A10 Networks devices
- Some proprietary TLS stacks

**Detection Method**:
- Tests TLS 1.0-1.2 with CBC ciphers
- Sends malformed padding in encrypted records
- Analyzes server error responses

**Severity**: HIGH

**Mitigation**:
- Update vulnerable TLS implementations
- Disable CBC cipher suites, prefer AEAD ciphers (GCM, ChaCha20-Poly1305)
- Enable TLS 1.3 which doesn't support CBC mode

### 3. Zombie POODLE - CVE-2019-5592

**Description**: Zombie POODLE is a padding oracle that occurs when servers reveal MAC validity through different error responses or timing, even when padding is invalid. The server processes the MAC before validating padding, creating an observable side channel.

**Affected Systems**:
- F5 BIG-IP (fixed in specific versions)
- Citrix NetScaler (fixed in specific versions)
- Other load balancers and TLS terminators with CBC support

**Detection Method**:
```
1. Send TLS record with: Invalid Padding + Valid MAC structure
2. Send TLS record with: Invalid Padding + Invalid MAC
3. Compare server responses (alerts, timing, connection behavior)
4. If responses differ consistently → MAC validity oracle exists
5. Repeat 5 iterations for statistical confidence
```

**Technical Details**:
- Exploits processing order: MAC verification before padding check
- Attacker can determine if MAC is correct despite invalid padding
- Enables plaintext recovery similar to classic POODLE
- Requires 256 requests per byte on average (same as classic POODLE)

**Severity**: HIGH

**Mitigation**:
- Disable CBC cipher suites (AES-CBC, 3DES-CBC)
- Use AEAD ciphers only (AES-GCM, CHACHA20-POLY1305)
- Update vulnerable F5/Citrix devices
- Enable TLS 1.3

### 4. GOLDENDOODLE - CVE-2019-5592

**Description**: GOLDENDOODLE exploits servers that provide different error responses for valid vs invalid padding, even with consistent MAC handling. This is the inverse of Zombie POODLE - padding validity leaks through error differentiation.

**Affected Systems**:
- Same as Zombie POODLE
- Devices with improper CBC padding validation

**Detection Method**:
```
1. Send TLS record with: Valid Padding + Invalid MAC
2. Send TLS record with: Invalid Padding + Invalid MAC
3. Analyze error message types and timing
4. If padding validity affects observable behavior → oracle exists
5. Repeat 5 iterations for consistency
```

**Technical Details**:
- More efficient than classic POODLE
- Uppercase hex session ID requires only 16 requests per byte
- Significantly faster than 256 requests/byte in POODLE
- Uses golden ratio-based padding patterns for optimization

**Severity**: HIGH

**Mitigation**:
- Same as Zombie POODLE
- Ensure constant-time padding validation
- Use authenticated encryption (AEAD)

### 5. Sleeping POODLE - CVE-2019-5592

**Description**: A timing-based padding oracle where servers take measurably different amounts of time to process valid vs invalid padding, even if error messages are identical.

**Affected Systems**:
- Servers with non-constant-time CBC implementation
- Systems without timing attack countermeasures

**Detection Method**:
```
1. Send 10 samples with: Valid Padding + Invalid MAC
2. Send 10 samples with: Invalid Padding + Invalid MAC
3. Measure response times for each
4. Calculate statistical difference
5. If timing difference > 5ms threshold → timing oracle exists
6. Include 100ms delays between samples to avoid rate limiting
```

**Technical Details**:
- Exploits computational differences in padding validation
- Valid padding may trigger more processing (MAC check, decryption)
- Invalid padding may fail fast
- Requires statistical analysis over multiple samples
- Similar to Lucky13 but specific to padding oracles

**Severity**: MEDIUM (harder to exploit remotely, network jitter)

**Mitigation**:
- Implement constant-time padding validation
- Use AEAD ciphers
- Add random delays to error responses (limited effectiveness)

### 6. OpenSSL 0-Length Fragment - CVE-2011-4576

**Description**: OpenSSL versions before 0.9.8s and 1.0.0f do not properly initialize data structures for CBC padding when processing zero-length TLS fragments, potentially leaking memory contents.

**Affected Systems**:
- OpenSSL < 0.9.8s
- OpenSSL 1.x < 1.0.0f
- Systems using vulnerable OpenSSL versions

**Detection Method**:
```
1. Establish TLS connection with CBC cipher
2. Send zero-length Application Data record (only TLS header, no payload)
3. Observe server behavior:
   - Accepts record without error → vulnerable
   - Closes connection/sends alert → not vulnerable
4. Repeat 3 times for consistency
```

**Technical Details**:
- Related to improper memory initialization
- Zero-length encrypted records should be rejected
- Can leak uninitialized padding bytes
- Information disclosure vulnerability

**Severity**: HIGH

**Mitigation**:
- Update OpenSSL to 0.9.8s, 1.0.0f or later
- Use modern TLS libraries (OpenSSL 1.1.1+, BoringSSL, LibreSSL)
- Disable CBC ciphers entirely

## Detection Architecture

### Implementation Structure

```
src/vulnerabilities/poodle.rs
├── PoodleTester                    # Main test orchestrator
├── PoodleVariant                   # Enum of all variants
├── PoodleVariantResult             # Individual test result
├── PoodleTestResult                # Combined results
├── TimingData                      # Timing analysis data
├── MalformedRecordType             # Types of crafted records
└── ServerResponse                  # Parsed server behavior
```

### Detection Flow

```
1. test_all_variants()
   ├── Check CBC cipher support (prerequisite)
   ├── Test Classic POODLE (SSLv3)
   ├── Test TLS POODLE
   ├── Test Zombie POODLE
   │   ├── Send invalid_padding + valid_mac (5x)
   │   ├── Send invalid_padding + invalid_mac (5x)
   │   └── Analyze response differences
   ├── Test GOLDENDOODLE
   │   ├── Send valid_padding + invalid_mac (5x)
   │   ├── Send invalid_padding + invalid_mac (5x)
   │   └── Analyze error differentiation
   ├── Test Sleeping POODLE
   │   ├── Time valid_padding responses (10x)
   │   ├── Time invalid_padding responses (10x)
   │   └── Statistical timing analysis
   └── Test OpenSSL 0-Length
       ├── Send zero-length TLS records (3x)
       └── Check acceptance behavior
```

### Malformed Record Types

**Invalid Padding + Valid MAC Structure**:
```
[App Data Header][Encrypted Data][Valid MAC][Invalid Padding Bytes]
                                              └─ Inconsistent values
```

**Valid Padding + Invalid MAC**:
```
[App Data Header][Encrypted Data][Invalid MAC (0xFF)][Valid PKCS#7 Padding]
                                                      └─ All bytes = 0x06
```

**Invalid Padding + Invalid MAC**:
```
[App Data Header][Encrypted Data][Invalid MAC][Invalid Padding]
```

**Zero-Length Record**:
```
[App Data Header][Length: 0x0000]
```

## Integration with VulnerabilityScanner

The POODLE variants are integrated into the main vulnerability scanner in `src/vulnerabilities/tester.rs`:

```rust
// In test_all() method:
let poodle_variants = self.test_poodle_variants().await?;
results.extend(poodle_variants);
```

Each variant produces a separate `VulnerabilityResult` with:
- Specific CVE reference
- Severity rating
- Detailed explanation
- Timing data (for Sleeping POODLE)

## Testing

### Unit Tests

```bash
# Run all POODLE tests
cargo test --lib vulnerabilities::poodle

# Run with output
cargo test --lib vulnerabilities::poodle -- --nocapture

# Run ignored network tests (requires internet)
cargo test --lib vulnerabilities::poodle -- --ignored
```

### Integration Testing

```bash
# Test against modern server (should be not vulnerable)
cargo test test_all_variants_modern_server -- --ignored

# Expected output: All 6 variants tested, none vulnerable
```

### Test Coverage

- ✅ PoodleVariant enum methods (name, cve, description)
- ✅ Malformed record construction
- ✅ ClientHello CBC structure
- ✅ Timing data structure
- ✅ Network tests (ignored by default)

## Performance Considerations

**Total Test Time per Target**:
- CBC cipher check: ~2-5 seconds
- Zombie POODLE: ~10 seconds (5 iterations × 2 record types)
- GOLDENDOODLE: ~10 seconds (5 iterations × 2 record types)
- Sleeping POODLE: ~20 seconds (10 samples × 2 + delays)
- OpenSSL 0-Length: ~6 seconds (3 iterations)

**Total: ~45-50 seconds** for complete POODLE variant testing

**Optimization Strategies**:
1. CBC support check happens once and gates all tests
2. Tests run sequentially to avoid overwhelming target
3. Connection timeouts prevent hanging
4. Sleeping POODLE includes 100ms delays between samples

## False Positive Prevention

**Zombie POODLE**:
- Requires consistent differential behavior across 5 iterations
- Compares alert types and timing
- 10ms timing threshold to avoid network jitter false positives

**GOLDENDOODLE**:
- Same consistency requirements as Zombie POODLE
- Analyzes both alert types and timing patterns

**Sleeping POODLE**:
- 10 samples for statistical significance
- 5ms threshold (conservative)
- Calculates averages to smooth network variations
- Reports timing data for manual verification

**OpenSSL 0-Length**:
- Requires 2/3 iterations showing vulnerability
- Distinguishes between connection rejection and acceptance

## Output Format

### Terminal Output
```
[VULN] Zombie POODLE (CVE-2019-5592) - HIGH
       Vulnerable to Zombie POODLE - Observable MAC validity oracle detected (5 iterations)

[VULN] Sleeping POODLE (CVE-2019-5592) - MEDIUM
       Vulnerable to Sleeping POODLE - Timing oracle detected:
       valid=15.32ms, invalid=8.45ms, diff=6.87ms

[SAFE] GOLDENDOODLE (CVE-2019-5592) - INFO
       Not vulnerable to GOLDENDOODLE - No padding oracle detected
```

### JSON Output
```json
{
  "vuln_type": "ZombiePoodle",
  "vulnerable": true,
  "details": "Vulnerable to Zombie POODLE - Observable MAC validity oracle detected (5 iterations)",
  "cve": "CVE-2019-5592",
  "cwe": "CWE-310",
  "severity": "High"
}
```

## References

### Research Papers & Presentations
- **Original POODLE**: "This POODLE Bites: Exploiting The SSL 3.0 Fallback" - Bodo Möller, Thai Duong, Krzysztof Kotowicz (2014)
- **Zombie POODLE & GOLDENDOODLE**: Craig Young, Tripwire VERT, Black Hat Asia 2019
- **SSL Labs Analysis**: https://blog.qualys.com/product-tech/2019/04/22/zombie-poodle-and-goldendoodle-vulnerabilities

### CVE References
- **CVE-2014-3566**: POODLE (SSLv3)
- **CVE-2014-8730**: POODLE TLS
- **CVE-2019-5592**: Zombie POODLE, GOLDENDOODLE, Sleeping POODLE
- **CVE-2011-4576**: OpenSSL 0-Length Fragment

### Tools
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **testssl.sh**: https://github.com/drwetter/testssl.sh
- **Tripwire padcheck**: https://github.com/Tripwire/padcheck

## Contributing

To add new POODLE variants or improve detection:

1. Add variant to `PoodleVariant` enum
2. Implement detection method in `PoodleTester`
3. Add to `test_all_variants()` orchestration
4. Create unit tests
5. Add VulnerabilityType to mod.rs
6. Update documentation

## License

This implementation is part of CipherRun and is licensed under GPL-3.0.

**Author**: Marc Rivero López
**Maintainer**: CipherRun Security Team
