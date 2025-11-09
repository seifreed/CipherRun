# Compliance Framework Engine

CipherRun includes a comprehensive compliance framework engine that evaluates TLS/SSL configurations against industry standards and regulatory requirements.

## Overview

The compliance framework engine automatically assesses scan results against established security frameworks, providing detailed reports on compliance status, violations, and remediation guidance.

## Supported Frameworks

CipherRun supports 7 major compliance frameworks:

### 1. PCI-DSS v4.0.1
**Payment Card Industry Data Security Standard**

Required for organizations that handle credit card data. Ensures strong cryptography and secure transmission of cardholder data.

- **ID**: `pci-dss-v4` or `pci-dss` or `pci`
- **Organization**: PCI Security Standards Council
- **Effective Date**: March 31, 2024
- **Key Requirements**:
  - TLS 1.2 and TLS 1.3 only
  - No weak ciphers (NULL, EXPORT, DES, 3DES, RC4, MD5)
  - Forward secrecy required
  - Minimum 2048-bit RSA or 256-bit ECC keys
  - SHA-2 family signatures only
  - Valid certificate chains
  - AEAD ciphers preferred
  - No known vulnerabilities

### 2. NIST SP 800-52 Revision 2
**Guidelines for TLS Implementations**

Federal guidance for selecting, configuring, and using TLS implementations.

- **ID**: `nist-sp800-52r2` or `nist`
- **Organization**: National Institute of Standards and Technology
- **Effective Date**: August 1, 2019
- **Key Requirements**:
  - TLS 1.2 and TLS 1.3 only
  - Forward secrecy mandatory
  - AEAD ciphers preferred
  - No weak/NULL encryption
  - Certificate validation required
  - Minimum 2048-bit RSA or 256-bit ECC keys
  - SHA-2 signatures
  - CBC mode discouraged in TLS 1.2
  - Certificate expiration monitoring (90-day warning)

### 3. HIPAA
**Health Insurance Portability and Accountability Act**

Technical safeguards for protecting electronic Protected Health Information (ePHI).

- **ID**: `hipaa`
- **Organization**: U.S. Department of Health and Human Services
- **Effective Date**: April 21, 2003
- **Key Requirements**:
  - Strong encryption for ePHI transmission (TLS 1.2/1.3)
  - Integrity controls (AEAD ciphers)
  - No weak encryption algorithms
  - Proper key management (2048-bit RSA, 256-bit ECC minimum)
  - Certificate validation and monitoring
  - No known vulnerabilities
  - Strong hash functions (SHA-2 family)
  - Forward secrecy recommended

### 4. SOC 2 Type II
**Service Organization Control 2**

Trust Services Criteria for security, availability, and confidentiality of cloud/SaaS providers.

- **ID**: `soc2` or `soc-2`
- **Organization**: AICPA (American Institute of CPAs)
- **Effective Date**: January 1, 2017
- **Key Requirements**:
  - Encryption in transit (TLS 1.2/1.3)
  - Strong key management
  - No weak cipher suites
  - Data integrity during transmission (AEAD)
  - Certificate lifecycle monitoring (90-day warning)
  - Security update management
  - Strong cryptographic hash functions
  - Perfect forward secrecy

### 5. Mozilla Modern
**Maximum Security TLS Configuration**

Mozilla's recommended configuration for maximum security (may sacrifice some compatibility).

- **ID**: `mozilla-modern` or `modern`
- **Organization**: Mozilla Foundation
- **Version**: 5.7
- **Key Requirements**:
  - **TLS 1.3 ONLY** (no TLS 1.2)
  - Only modern AEAD cipher suites
  - Strong certificate keys (2048-bit RSA, 256-bit ECC minimum)
  - SHA-2 signatures only
  - Valid certificate chains
  - Forward secrecy mandatory (built into TLS 1.3)
  - No known vulnerabilities

**Use Case**: High-security applications where all clients support TLS 1.3

### 6. Mozilla Intermediate
**Balanced Security and Compatibility**

Mozilla's recommended configuration for most websites (recommended for production).

- **ID**: `mozilla-intermediate` or `intermediate`
- **Organization**: Mozilla Foundation
- **Version**: 5.7
- **Key Requirements**:
  - TLS 1.2 and TLS 1.3
  - Recommended cipher suites (prioritizing AEAD)
  - Forward secrecy required
  - AEAD ciphers preferred
  - Strong certificate keys
  - SHA-2 signatures
  - Valid certificate chains
  - Certificate lifecycle management (90-day warning)
  - No known vulnerabilities

**Use Case**: Most websites and applications (~99% browser compatibility)

### 7. GDPR
**General Data Protection Regulation**

EU regulation requiring appropriate technical measures to protect personal data.

- **ID**: `gdpr`
- **Organization**: European Union
- **Effective Date**: May 25, 2018
- **Key Requirements**:
  - State-of-the-art encryption (TLS 1.2/1.3)
  - Confidentiality and integrity measures
  - Data integrity (AEAD ciphers)
  - Appropriate cryptographic key strength
  - Identity verification (certificate validation)
  - Secure hash functions
  - Forward secrecy for long-term protection
  - Resilience against vulnerabilities
  - Regular security testing (certificate monitoring)

## Usage

### List Available Frameworks

```bash
cipherrun --list-compliance
```

Output:
```
Available Compliance Frameworks:

  pci-dss-v4 - PCI-DSS v4.0.1 - Payment Card Industry Data Security Standard
  nist-sp800-52r2 - NIST SP 800-52 Revision 2 - Guidelines for TLS
  hipaa - HIPAA - Health Insurance Portability and Accountability Act
  soc2 - SOC 2 - Service Organization Control 2
  mozilla-modern - Mozilla Modern TLS Configuration
  mozilla-intermediate - Mozilla Intermediate TLS Configuration
  gdpr - GDPR - General Data Protection Regulation (encryption requirements)

Usage: cipherrun --compliance <FRAMEWORK_ID> <TARGET>
Example: cipherrun --compliance pci-dss-v4 example.com:443
```

### Basic Compliance Check

```bash
# Check PCI-DSS compliance
cipherrun --compliance pci-dss-v4 example.com:443

# Check NIST compliance
cipherrun --compliance nist example.com:443

# Check HIPAA compliance
cipherrun --compliance hipaa example.com:443
```

### Output Formats

#### Terminal Output (Default)

```bash
cipherrun --compliance pci-dss-v4 example.com:443
```

Output:
```
======================================================================
Compliance Report: PCI-DSS v4.0.1
======================================================================
Framework:    PCI-DSS v4.0.1 v4.0.1
Organization: PCI Security Standards Council
Target:       example.com:443
Scan Time:    2025-01-09 15:30:00 UTC
Overall Status: FAIL

Summary:
  Total Requirements: 8
  ✓ Passed:  6
  ✗ Failed:  2
  ⚠ Warnings: 0

Failed Requirements:
--------------------------------------------------------------------

[CRITICAL] PCI-4.2.1 - Strong Cryptography - TLS 1.2+
  Category:    Protocol Security
  Status:      FAIL

  Violation:   Prohibited Protocol
  Description: TLS 1.0 is prohibited by this compliance framework
  Evidence:    Server accepts TLS 1.0 connections

  Remediation:
    Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on all systems...
    Configure servers to accept only TLS 1.2 and TLS 1.3 connections.

[CRITICAL] PCI-4.2.2 - Weak Cipher Prohibition
  Category:    Cipher Security
  Status:      FAIL

  Violation:   Prohibited Cipher Suite
  Description: Weak or prohibited cipher suite detected for TLS 1.2
  Evidence:    TLS_RSA_WITH_3DES_EDE_CBC_SHA (ECDHE-RSA-DES-CBC3-SHA)

  Remediation:
    Remove and disable all weak cipher suites including:
    - NULL ciphers (provide no encryption)
    - EXPORT ciphers (intentionally weakened for export)
    - DES and 3DES (obsolete encryption)
    ...
======================================================================
```

#### JSON Output

```bash
cipherrun --compliance pci-dss-v4 --compliance-format json example.com:443
```

```json
{
  "framework": {
    "id": "pci-dss-v4",
    "name": "PCI-DSS v4.0.1",
    "version": "4.0.1",
    "organization": "PCI Security Standards Council"
  },
  "target": "example.com:443",
  "scan_timestamp": "2025-01-09T15:30:00Z",
  "overall_status": "fail",
  "summary": {
    "total": 8,
    "passed": 6,
    "failed": 2,
    "warnings": 0
  },
  "requirements": [...]
}
```

#### CSV Output

```bash
cipherrun --compliance pci-dss-v4 --compliance-format csv example.com:443 > report.csv
```

Output:
```csv
Requirement ID,Name,Category,Severity,Status,Violations,Evidence
PCI-4.2.1,Strong Cryptography,Protocol Security,Critical,FAIL,Prohibited Protocol,Server accepts TLS 1.0 connections
PCI-4.2.2,Weak Cipher Prohibition,Cipher Security,Critical,FAIL,Prohibited Cipher Suite,TLS_RSA_WITH_3DES_EDE_CBC_SHA
...
```

#### HTML Output

```bash
cipherrun --compliance pci-dss-v4 --compliance-format html example.com:443 > report.html
```

Generates a formatted HTML report with:
- Framework metadata
- Summary statistics
- Color-coded requirement status
- Detailed violation information
- Remediation guidance

### CI/CD Integration

The compliance engine exits with a non-zero status code if compliance fails, making it perfect for CI/CD pipelines:

```bash
#!/bin/bash
# Fail the build if PCI-DSS compliance is not met
cipherrun --compliance pci-dss-v4 example.com:443 --compliance-format json > compliance.json

if [ $? -ne 0 ]; then
  echo "COMPLIANCE FAILURE: Server does not meet PCI-DSS requirements"
  exit 1
fi
```

### Example: GitHub Actions

```yaml
name: TLS Compliance Check
on: [push]
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install CipherRun
        run: cargo install cipherrun
      - name: Check PCI-DSS Compliance
        run: |
          cipherrun --compliance pci-dss-v4 \
                    --compliance-format json \
                    production.example.com:443 > compliance-report.json
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: compliance-report
          path: compliance-report.json
```

## Custom Framework Definitions

You can create custom compliance frameworks by writing YAML files.

### Framework YAML Structure

```yaml
id: custom-framework
name: Custom TLS Security Framework
version: 1.0
description: Custom security requirements for internal use
organization: Your Organization
effective_date: 2025-01-01

requirements:
  - id: CUSTOM-1
    name: Requirement Name
    description: Detailed description of what is required
    category: Protocol Security  # or Cipher Security, Certificate Security, Vulnerability
    severity: critical  # critical, high, medium, low, info
    remediation: |
      Step-by-step remediation guidance...
    rules:
      - type: ProtocolVersion
        allowed:
          - TLS 1.3
        denied:
          - SSLv2
          - SSLv3
          - TLS 1.0
          - TLS 1.1
          - TLS 1.2
```

### Rule Types

#### ProtocolVersion
Check which TLS/SSL protocol versions are enabled.

```yaml
- type: ProtocolVersion
  allowed:
    - TLS 1.2
    - TLS 1.3
  denied:
    - SSLv2
    - SSLv3
    - TLS 1.0
    - TLS 1.1
```

#### CipherSuite
Check cipher suites using pattern matching (regex).

```yaml
- type: CipherSuite
  # Patterns to allow (optional)
  allowed_patterns:
    - ".*_GCM.*"
    - ".*_CHACHA20_POLY1305.*"
  # Patterns to deny (optional)
  denied_patterns:
    - ".*_NULL_.*"
    - ".*_EXPORT_.*"
    - ".*_DES_.*"
    - ".*_3DES_.*"
    - ".*_RC4_.*"
  # Patterns for preferred ciphers (optional)
  preferred_patterns:
    - ".*_GCM.*"
```

#### CertificateKeySize
Check minimum key sizes.

```yaml
- type: CertificateKeySize
  min_rsa_bits: 2048
  min_ecc_bits: 256
```

#### SignatureAlgorithm
Check certificate signature algorithms.

```yaml
- type: SignatureAlgorithm
  allowed:
    - sha256
    - sha384
    - sha512
  denied:
    - md5
    - sha1
```

#### ForwardSecrecy
Require forward secrecy (PFS).

```yaml
- type: ForwardSecrecy
  required: true
```

#### CertificateValidation
Validate certificate properties.

```yaml
- type: CertificateValidation
  require_valid_chain: true
  require_unexpired: true
  require_hostname_match: true
```

#### CertificateExpiration
Check for upcoming certificate expiration.

```yaml
- type: CertificateExpiration
  max_days_until_expiration: 90  # Warn if expiring within 90 days
```

#### Vulnerability
Check for known TLS/SSL vulnerabilities.

```yaml
- type: Vulnerability
  # Checks for: Heartbleed, POODLE, BEAST, CRIME, FREAK, Logjam, DROWN, etc.
```

### Loading Custom Frameworks

```bash
# Custom frameworks must be placed in data/compliance/ directory
cp my-framework.yaml /path/to/cipherrun/data/compliance/

# Use custom framework by ID
cipherrun --compliance my-framework example.com:443
```

## Compliance Reports

### Report Structure

Each compliance report includes:

1. **Framework Metadata**
   - Framework name, version, organization
   - Effective date

2. **Scan Metadata**
   - Target hostname and port
   - Scan timestamp
   - Overall compliance status (PASS/FAIL/WARNING)

3. **Summary Statistics**
   - Total requirements evaluated
   - Number passed/failed/warnings
   - Number not applicable

4. **Requirement Results**
   - Requirement ID and name
   - Category and severity
   - Status (PASS/FAIL/WARNING/N/A)
   - Violations (if any)
   - Evidence
   - Remediation guidance

### Severity Levels

- **Critical**: Must be addressed immediately (e.g., weak encryption, known vulnerabilities)
- **High**: Important security issues (e.g., weak keys, legacy protocols)
- **Medium**: Recommended improvements (e.g., AEAD cipher preference)
- **Low**: Minor recommendations
- **Info**: Informational findings

## Framework Selection Guide

| Use Case | Recommended Framework |
|----------|----------------------|
| Payment card processing | PCI-DSS v4 |
| U.S. Federal systems | NIST SP 800-52r2 |
| Healthcare (U.S.) | HIPAA |
| SaaS/Cloud providers | SOC 2 |
| EU personal data | GDPR |
| Maximum security | Mozilla Modern |
| Production websites | Mozilla Intermediate |

## Best Practices

1. **Regular Compliance Checks**
   - Run compliance checks monthly or after any configuration changes
   - Monitor for upcoming certificate expirations (90-day warning)

2. **Multiple Frameworks**
   - Organizations may need to comply with multiple frameworks
   - Run checks against all applicable frameworks
   - Address the most restrictive requirements

3. **Automated Testing**
   - Integrate compliance checks into CI/CD pipelines
   - Fail builds on compliance violations
   - Store compliance reports as artifacts

4. **Documentation**
   - Keep compliance reports for audit purposes
   - Document remediation actions
   - Track compliance status over time

5. **Remediation Priority**
   - Address CRITICAL violations immediately
   - Plan for HIGH severity fixes
   - Consider MEDIUM/LOW improvements

## Frequently Asked Questions

### Q: Which framework should I use?

**A**: Use the framework(s) required by your industry regulations or contractual obligations. If not specified:
- **General use**: Mozilla Intermediate
- **Maximum security**: Mozilla Modern
- **Payment processing**: PCI-DSS v4
- **Healthcare**: HIPAA
- **Cloud/SaaS**: SOC 2
- **EU operations**: GDPR

### Q: Can I check against multiple frameworks?

**A**: Yes, run multiple compliance checks:

```bash
cipherrun --compliance pci-dss-v4 example.com:443 > pci-report.txt
cipherrun --compliance hipaa example.com:443 > hipaa-report.txt
cipherrun --compliance soc2 example.com:443 > soc2-report.txt
```

### Q: What happens if compliance fails?

**A**: CipherRun exits with status code 1, making it suitable for CI/CD integration. The report shows:
- Which requirements failed
- Evidence of violations
- Remediation guidance

### Q: Can I create custom compliance frameworks?

**A**: Yes! Create a YAML file following the framework definition structure and place it in `data/compliance/`. See the "Custom Framework Definitions" section above.

### Q: How often should I run compliance checks?

**A**:
- **Automated**: Every deployment (CI/CD)
- **Manual**: Monthly or after configuration changes
- **Audit**: Before compliance audits
- **Monitoring**: Certificate expiration checks (90 days)

### Q: What if my server fails compliance?

**A**: Review the compliance report:
1. Identify failed requirements
2. Review violations and evidence
3. Follow remediation guidance
4. Apply fixes to configuration
5. Re-run compliance check
6. Document changes for audit trail

## Technical Details

### Architecture

The compliance engine consists of:

1. **Framework Loader** (`loader.rs`)
   - Loads YAML framework definitions
   - Supports built-in and custom frameworks

2. **Compliance Engine** (`engine.rs`)
   - Orchestrates evaluation process
   - Maps scan results to requirements

3. **Rule Checkers** (`checker.rs`)
   - Protocol version checking
   - Cipher suite analysis
   - Certificate validation
   - Vulnerability detection

4. **Reporter** (`reporter.rs`)
   - Terminal output (colored, formatted)
   - JSON export
   - CSV export
   - HTML generation

### Integration Points

The compliance engine integrates with:
- Protocol testing (`src/protocols/`)
- Cipher testing (`src/ciphers/`)
- Certificate analysis (`src/certificates/`)
- Vulnerability scanning (`src/vulnerabilities/`)

All scan results are automatically available for compliance evaluation.

## Support

For issues, feature requests, or custom framework development:
- GitHub: https://github.com/seifreed/cipherrun
- Documentation: See README.md

## License

The compliance framework engine is part of CipherRun and licensed under GPL-3.0.
