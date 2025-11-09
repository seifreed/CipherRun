# Compliance Framework Engine - Quick Start Guide

## 5-Minute Quick Start

### List Available Frameworks
```bash
cipherrun --list-compliance
```

### Run Your First Compliance Check
```bash
# Check PCI-DSS compliance
cipherrun --compliance pci-dss-v4 example.com:443
```

### Generate a Report
```bash
# HTML report
cipherrun --compliance pci-dss-v4 --compliance-format html example.com:443 > report.html

# JSON report
cipherrun --compliance nist --compliance-format json example.com:443 > report.json

# CSV report
cipherrun --compliance hipaa --compliance-format csv example.com:443 > report.csv
```

## Framework Selection Cheat Sheet

| Framework ID | Use When | Strictness |
|--------------|----------|------------|
| `pci-dss-v4` | Processing payments | ⭐⭐⭐⭐⭐ Critical |
| `nist-sp800-52r2` | U.S. federal systems | ⭐⭐⭐⭐ High |
| `hipaa` | Healthcare data (U.S.) | ⭐⭐⭐⭐ High |
| `soc2` | Cloud/SaaS provider | ⭐⭐⭐⭐ High |
| `gdpr` | EU personal data | ⭐⭐⭐⭐ High |
| `mozilla-modern` | Maximum security | ⭐⭐⭐⭐⭐ TLS 1.3 only |
| `mozilla-intermediate` | Production websites | ⭐⭐⭐ Balanced |

## Common Commands

```bash
# List frameworks
cipherrun --list-compliance

# Basic check
cipherrun --compliance <FRAMEWORK> <TARGET>

# With custom format
cipherrun --compliance <FRAMEWORK> --compliance-format <FORMAT> <TARGET>

# Examples
cipherrun --compliance pci-dss-v4 example.com:443
cipherrun --compliance nist example.com:443
cipherrun --compliance mozilla-intermediate example.com:443
```

## Output Formats

| Format | Flag | Best For |
|--------|------|----------|
| Terminal | `--compliance-format terminal` (default) | Human reading |
| JSON | `--compliance-format json` | Automation/CI/CD |
| CSV | `--compliance-format csv` | Spreadsheets |
| HTML | `--compliance-format html` | Reports/sharing |

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: PCI-DSS Compliance Check
  run: |
    cipherrun --compliance pci-dss-v4 \
              --compliance-format json \
              ${{ env.TARGET }} > compliance.json
```

### GitLab CI Example
```yaml
compliance_check:
  script:
    - cipherrun --compliance pci-dss-v4 --compliance-format json $TARGET
  artifacts:
    paths:
      - compliance.json
```

### Exit Codes
- **0**: Compliance PASS
- **1**: Compliance FAIL (use for build gates)

## Understanding Results

### Status Indicators
- **PASS**: All requirements met ✓
- **FAIL**: Critical violations found ✗
- **WARNING**: Minor issues detected ⚠

### Severity Levels
- **Critical**: Must fix immediately (broken protocols, weak encryption)
- **High**: Important security issues (weak keys, old signatures)
- **Medium**: Recommended improvements (cipher preferences)
- **Low**: Minor recommendations
- **Info**: Informational findings

## Quick Remediation Guide

### Common Failures

#### "TLS 1.0/1.1 enabled"
```nginx
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;

# Apache
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
```

#### "Weak ciphers detected"
```nginx
# Nginx (Mozilla Intermediate)
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

# Apache
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
```

#### "Certificate key too small"
```bash
# Generate new 2048-bit RSA key
openssl genrsa -out private.key 2048

# Generate new 256-bit ECC key
openssl ecparam -name prime256v1 -genkey -out private.key
```

## Framework Requirements Overview

### PCI-DSS v4.0.1
- ✓ TLS 1.2/1.3 only
- ✓ No weak ciphers (DES, 3DES, RC4, MD5)
- ✓ Forward secrecy
- ✓ 2048-bit RSA or 256-bit ECC minimum
- ✓ SHA-2 signatures
- ✓ Valid certificates
- ✓ No vulnerabilities

### NIST SP 800-52r2
- ✓ TLS 1.2/1.3 only
- ✓ Forward secrecy mandatory
- ✓ AEAD ciphers preferred
- ✓ No weak/NULL encryption
- ✓ Certificate validation
- ✓ 2048-bit RSA minimum
- ✓ SHA-2 signatures

### Mozilla Modern
- ✓ **TLS 1.3 ONLY**
- ✓ Modern AEAD ciphers only
- ✓ Strong keys
- ✓ No CBC mode
- ✓ Perfect for new deployments

### Mozilla Intermediate
- ✓ TLS 1.2 + TLS 1.3
- ✓ Balanced security/compatibility
- ✓ ~99% browser support
- ✓ Recommended for production

## Getting Help

### Full Documentation
```bash
cat COMPLIANCE.md
```

### Report Issues
- GitHub: https://github.com/seifreed/cipherrun/issues

### Community
- Discussions: https://github.com/seifreed/cipherrun/discussions

## Tips and Tricks

### 1. Start with Mozilla Intermediate
Most websites should start here - it's the best balance.

### 2. Test Before Deploying
Always run compliance checks in staging first.

### 3. Automate Everything
Add compliance checks to your CI/CD pipeline.

### 4. Monitor Certificate Expiry
Most frameworks include 90-day expiration warnings.

### 5. Keep Software Updated
Regular updates prevent vulnerability failures.

### 6. Document Everything
Save compliance reports for audit trails.

## Next Steps

1. **Choose your framework** based on your industry/requirements
2. **Run a baseline scan** to see where you stand
3. **Review failures** and understand what needs fixing
4. **Implement fixes** following remediation guidance
5. **Re-scan** to verify compliance
6. **Automate** by adding to CI/CD
7. **Monitor** regularly (monthly recommended)

---

For complete documentation, see [COMPLIANCE.md](COMPLIANCE.md)
