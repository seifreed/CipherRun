# CipherRun Policy-as-Code Engine

## Overview

The CipherRun Policy-as-Code Engine provides a flexible, declarative way to enforce TLS/SSL security policies across your infrastructure. Define security requirements in YAML files and automatically validate scan results against them - perfect for CI/CD pipelines, compliance automation, and continuous security monitoring.

## Quick Start

### Basic Usage

1. **Create a policy file** (e.g., `security-policy.yaml`):

```yaml
policy:
  name: "Production TLS Policy"
  version: "1.0"

  protocols:
    required: ["TLSv1.2", "TLSv1.3"]
    prohibited: ["SSLv2", "SSLv3", "TLSv1.0"]
    action: FAIL

  certificates:
    min_key_size: 2048
    max_days_until_expiry: 30
    action: FAIL
```

2. **Run scan with policy enforcement**:

```bash
cipherrun example.com:443 --policy security-policy.yaml --enforce
```

3. **CI/CD Integration**:

```bash
# Exit code 0 if compliant, 1 if violations found
cipherrun $TARGET --policy policy.yaml --enforce --policy-format json
```

## Policy File Structure

### Complete Policy Schema

```yaml
policy:
  # Metadata
  name: "Policy Name"              # Required
  version: "1.0"                   # Required
  description: "Policy description"
  organization: "Your Org"
  effective_date: "2025-01-01"

  # Inherit from another policy (optional)
  extends: "base-policy.yaml"

  # Protocol requirements
  protocols:
    required: ["TLSv1.2", "TLSv1.3"]
    prohibited: ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    action: FAIL  # FAIL, WARN, or INFO

  # Cipher suite requirements
  ciphers:
    min_strength: "HIGH"           # LOW, MEDIUM, HIGH
    require_forward_secrecy: true
    require_aead: false
    prohibited_patterns:
      - ".*_RC4_.*"
      - ".*_DES_.*"
      - ".*_MD5.*"
      - ".*_NULL_.*"
      - ".*_EXPORT_.*"
    required_patterns:
      - ".*_GCM$"                  # Prefer GCM ciphers
    action: FAIL

  # Certificate requirements
  certificates:
    min_key_size: 2048
    max_days_until_expiry: 30
    prohibited_signature_algorithms: ["SHA1", "MD5"]
    require_valid_trust_chain: true
    require_san: true
    require_hostname_match: true
    action: FAIL

  # Vulnerability thresholds
  vulnerabilities:
    max_critical: 0
    max_high: 0
    max_medium: 2
    prohibited:
      - "POODLE"
      - "BEAST"
      - "CRIME"
      - "Heartbleed"
    action: FAIL

  # Rating requirements (SSL Labs style)
  rating:
    min_grade: "A"
    min_score: 80
    action: WARN

  # Compliance framework mapping (future feature)
  compliance:
    frameworks:
      - pci-dss-v4
      - nist-sp800-52r2
    require_all: true
    action: FAIL

  # Exceptions
  exceptions:
    - domain: "legacy.example.com"
      rules:
        - "protocols.prohibited"
        - "ciphers.prohibited_patterns"
      reason: "Legacy system, migration scheduled Q2 2026"
      expires: "2026-06-30"
      approved_by: "CISO"
      ticket: "SEC-1234"

    - domain: "*.internal.example.com"
      rules: ["certificates.max_days_until_expiry"]
      reason: "Internal systems use short-lived certs"
      expires: null  # No expiration
      approved_by: "Security Team"
```

## Policy Actions

Each policy rule supports three action levels:

- **FAIL**: Violation causes policy evaluation to fail (exit code 1 with `--enforce`)
- **WARN**: Violation logged as warning but doesn't fail policy
- **INFO**: Informational violation, no impact on pass/fail status

## Policy Rules Reference

### Protocol Policy

```yaml
protocols:
  required: ["TLSv1.2", "TLSv1.3"]      # Protocols that MUST be supported
  prohibited: ["SSLv2", "SSLv3"]        # Protocols that MUST NOT be supported
  action: FAIL
```

**Supported Protocol Names:**
- `SSLv2`, `SSLv3`
- `TLSv1.0`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`

### Cipher Policy

```yaml
ciphers:
  min_strength: "HIGH"                   # Minimum cipher strength
  require_forward_secrecy: true          # All ciphers must support FS
  require_aead: false                    # All ciphers must support AEAD
  prohibited_patterns:                   # Regex patterns to block
    - ".*_RC4_.*"
    - ".*_DES_.*"
  required_patterns:                     # At least one cipher must match
    - ".*_GCM$"
  action: FAIL
```

**Cipher Strength Levels:**
- `LOW`: 56-111 bits (allow weak ciphers)
- `MEDIUM`: 112-127 bits (allow medium strength)
- `HIGH`: 128+ bits only (require strong ciphers)

**Pattern Examples:**
- `".*_NULL_.*"` - Block NULL ciphers
- `".*_EXPORT_.*"` - Block EXPORT ciphers
- `".*_RC4_.*"` - Block RC4
- `".*_3DES_.*"` - Block 3DES
- `".*_GCM$"` - Require GCM ciphers
- `"^ECDHE_.*"` - Require ECDHE key exchange

### Certificate Policy

```yaml
certificates:
  min_key_size: 2048                     # Minimum RSA/DSA key size in bits
  max_days_until_expiry: 30              # Warn if cert expires within N days
  prohibited_signature_algorithms:       # Block weak signature algorithms
    - "SHA1"
    - "MD5"
  require_valid_trust_chain: true        # Certificate must chain to trusted CA
  require_san: true                      # Certificate must have SAN extension
  require_hostname_match: true           # Certificate must match target hostname
  action: FAIL
```

### Vulnerability Policy

```yaml
vulnerabilities:
  max_critical: 0                        # Maximum critical vulnerabilities allowed
  max_high: 0                            # Maximum high vulnerabilities allowed
  max_medium: 2                          # Maximum medium vulnerabilities allowed
  prohibited:                            # Specific vulnerabilities to block
    - "POODLE"
    - "BEAST"
    - "Heartbleed"
  action: FAIL
```

**Vulnerability Names:**
- `Heartbleed` (CVE-2014-0160)
- `POODLE` (CVE-2014-3566)
- `BEAST` (CVE-2011-3389)
- `CRIME` (CVE-2012-4929)
- `BREACH` (CVE-2013-3587)
- `DROWN` (CVE-2016-0800)
- `FREAK` (CVE-2015-0204)
- `LOGJAM` (CVE-2015-4000)
- `SWEET32` (CVE-2016-2183)
- `LUCKY13` (CVE-2013-0169)
- `ROBOT` (CVE-2017-13099)

### Rating Policy

```yaml
rating:
  min_grade: "A"                         # Minimum SSL Labs grade
  min_score: 80                          # Minimum SSL Labs score (0-100)
  action: WARN
```

**Supported Grades:**
`A+`, `A`, `A-`, `B`, `C`, `D`, `E`, `F`, `T` (trust issues), `M` (certificate mismatch)

## Policy Exceptions

Exceptions allow you to temporarily bypass policy rules for specific targets with proper documentation and approval.

### Exception Structure

```yaml
exceptions:
  - domain: "legacy.example.com"         # Target domain (supports wildcards)
    rules:                               # Rule paths to exempt
      - "protocols.prohibited"
      - "ciphers.min_strength"
    reason: "Legacy system migration"    # Business justification
    expires: "2026-06-30"                # Expiration date (YYYY-MM-DD)
    approved_by: "CISO"                  # Approver name/role
    ticket: "SEC-1234"                   # Optional tracking ticket
```

### Exception Domain Patterns

- **Exact match**: `"example.com"` - Only matches example.com
- **Wildcard subdomain**: `"*.example.com"` - Matches any.example.com, test.example.com, etc.
- **No domain filter**: `domain: null` - Applies to all targets

### Exception Rule Paths

Reference specific policy rules using dot notation:

- `"protocols.required"` - Required protocols check
- `"protocols.prohibited"` - Prohibited protocols check
- `"ciphers.min_strength"` - Minimum cipher strength check
- `"ciphers.require_forward_secrecy"` - Forward secrecy requirement
- `"ciphers.prohibited_patterns"` - Prohibited cipher patterns
- `"certificates.min_key_size"` - Minimum key size check
- `"certificates.max_days_until_expiry"` - Certificate expiry check
- `"vulnerabilities.max_critical"` - Critical vulnerability threshold
- `"vulnerabilities.prohibited"` - Prohibited specific vulnerabilities
- `"rating.min_grade"` - Minimum SSL Labs grade

### Exception Expiration

- **With expiration**: `expires: "2026-06-30"` - Exception expires on this date
- **No expiration**: `expires: null` - Exception never expires (use carefully!)

Expired exceptions are automatically ignored.

## Policy Inheritance

Policies can extend other policies using the `extends` keyword:

```yaml
# base-security.yaml
policy:
  name: "Base Security"
  version: "1.0"
  protocols:
    prohibited: ["SSLv2", "SSLv3"]
    action: FAIL

# production.yaml
policy:
  name: "Production"
  version: "1.0"
  extends: "base-security.yaml"  # Inherit base rules
  protocols:
    prohibited: ["SSLv2", "SSLv3", "TLSv1.0"]  # Override with stricter rules
    action: FAIL
```

**Inheritance Rules:**
- Child policy overrides parent for all fields except `exceptions`
- Exceptions from both parent and child are merged (combined)
- Paths are resolved relative to the policy file location

## CLI Usage

### Basic Policy Enforcement

```bash
# Scan and check against policy
cipherrun example.com:443 --policy security-policy.yaml

# Exit with error if violations found (for CI/CD)
cipherrun example.com:443 --policy security-policy.yaml --enforce

# Custom output format
cipherrun example.com:443 --policy policy.yaml --policy-format json
```

### Output Formats

- **terminal** (default): Human-readable colored output
- **json**: Machine-readable JSON output
- **csv**: CSV format for spreadsheets

### Exit Codes

- **0**: Policy compliance successful (no FAIL-level violations)
- **1**: Policy violations found (with `--enforce` flag)

## CI/CD Integration

### GitHub Actions

```yaml
name: TLS Security Compliance
on: [push, pull_request]

jobs:
  tls-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install CipherRun
        run: cargo install cipherrun

      - name: Scan and Enforce Policy
        run: |
          cipherrun ${{ secrets.PRODUCTION_DOMAIN }} \
            --policy policies/production.yaml \
            --enforce \
            --policy-format json \
            --json scan-results.json

      - name: Upload Results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: tls-scan-results
          path: scan-results.json
```

### GitLab CI

```yaml
tls_compliance:
  stage: test
  script:
    - cipherrun $PRODUCTION_DOMAIN --policy policies/production.yaml --enforce
  allow_failure: false
  only:
    - main
    - merge_requests
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('TLS Security Scan') {
            steps {
                sh '''
                    cipherrun ${PRODUCTION_DOMAIN} \
                        --policy policies/production.yaml \
                        --enforce \
                        --policy-format json \
                        --json results.json
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'results.json'
        }
    }
}
```

## Example Policies

CipherRun includes several example policies in `examples/policies/`:

### base-security.yaml
Foundation security policy with reasonable defaults:
- TLS 1.2+ required
- Strong cipher suites
- 2048-bit minimum key size
- 30-day certificate expiry warning
- Zero tolerance for critical vulnerabilities

### production.yaml
Strict policy for production environments:
- TLS 1.2+ only
- HIGH strength ciphers required
- Forward secrecy mandatory
- AEAD ciphers preferred
- Minimum SSL Labs grade A
- Example exceptions with expiration

### development.yaml
Relaxed policy for development:
- TLS 1.2+ recommended (WARN)
- More lenient cipher requirements
- Shorter certificate expiry threshold
- Higher vulnerability tolerance

### pci-compliant.yaml
PCI-DSS v4.0 compliant policy:
- TLS 1.2+ mandatory (PCI requirement)
- Strong ciphers only
- Zero vulnerability tolerance
- Minimum SSL Labs grade A
- Detailed compliance framework mapping

## Output Examples

### Terminal Output

```
============================================================
Policy Evaluation: Production TLS Security Policy v2.0
============================================================
Target: example.com:443
Evaluation Time: 2025-01-09 15:30:00 UTC
Result: FAIL (3 violations)

Violations:
------------------------------------------------------------

[FAIL] Prohibited Protocol Check
  Rule: protocols.prohibited
  Description: TLSv1.0 is prohibited but enabled
  Evidence: Server accepts TLSv1.0 connections
  Remediation: Disable TLSv1.0 in server configuration

[WARN] Certificate Expiry Check
  Rule: certificates.max_days_until_expiry
  Description: Certificate expires in 25 days (threshold: 30)
  Evidence: Valid until: 2025-02-03 12:00:00 UTC
  Remediation: Renew certificate before expiration

[FAIL] Prohibited Cipher Pattern
  Rule: ciphers.prohibited_patterns
  Description: Prohibited cipher detected: TLS_RSA_WITH_3DES_EDE_CBC_SHA
  Evidence: Protocol: TLSv1.2, Cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA (matches pattern: .*_3DES_.*)
  Remediation: Remove TLS_RSA_WITH_3DES_EDE_CBC_SHA from server configuration

Exceptions Applied:
------------------------------------------------------------
None

Summary:
  Total Checks: 15
  ✓ Passed: 12
  ✗ Failed: 2
  ⚠ Warnings: 1

Exit Code: 1 (FAIL)
```

### JSON Output

```json
{
  "policy_name": "Production TLS Security Policy",
  "policy_version": "2.0",
  "target": "example.com:443",
  "evaluation_time": "2025-01-09T15:30:00Z",
  "violations": [
    {
      "rule_path": "protocols.prohibited",
      "rule_name": "Prohibited Protocol Check",
      "action": "Fail",
      "description": "TLSv1.0 is prohibited but enabled",
      "evidence": "Server accepts TLSv1.0 connections",
      "remediation": "Disable TLSv1.0 in server configuration"
    }
  ],
  "exceptions_applied": [],
  "summary": {
    "total_checks": 15,
    "passed": 12,
    "failed": 2,
    "warnings": 1,
    "info": 0,
    "overall_result": "Fail"
  }
}
```

## Best Practices

### 1. Start with Base Policies
Use inheritance to build from foundation policies:
```yaml
extends: "base-security.yaml"
```

### 2. Use Meaningful Names and Versions
```yaml
name: "Production HTTPS Policy"
version: "2.1.0"
description: "Enforced on all public-facing HTTPS endpoints"
```

### 3. Document Exceptions Thoroughly
```yaml
exceptions:
  - domain: "legacy.app.com"
    reason: "Legacy Java 8 application, migration to Java 17 scheduled Q2 2026"
    ticket: "JIRA-1234"
    approved_by: "Security Architect (Jane Doe)"
    expires: "2026-06-30"
```

### 4. Set Expiration Dates
Always set expiration dates for temporary exceptions:
```yaml
expires: "2026-06-30"  # Review and renew if still needed
```

### 5. Use Appropriate Actions
- `FAIL`: Security-critical requirements
- `WARN`: Best practices and recommendations
- `INFO`: Informational checks

### 6. Test in Non-Production First
```bash
# Test policy against dev environment first
cipherrun dev.example.com --policy production.yaml
```

### 7. Version Control Your Policies
Store policies in Git alongside application code:
```
repo/
├── .github/workflows/tls-scan.yml
├── policies/
│   ├── base-security.yaml
│   ├── production.yaml
│   └── staging.yaml
```

## Troubleshooting

### Policy File Not Found
```bash
# Use absolute or relative path
cipherrun example.com --policy ./policies/production.yaml

# Or set base path
cipherrun example.com --policy policies/production.yaml
```

### Invalid YAML Syntax
```
Error: Failed to parse policy YAML: invalid type: string "INVALID", expected one of...
```
- Check YAML syntax using a validator
- Ensure proper indentation (2 spaces)
- Validate enum values (FAIL, WARN, INFO)

### Exception Not Applied
- Verify domain pattern matches target hostname
- Check if exception has expired
- Ensure rule path matches exactly

### Policy Inheritance Issues
- Verify parent policy file exists
- Use relative paths from policy file location
- Check for circular dependencies

## Advanced Features

### Dynamic Exception Management
Integrate with ticketing systems:
```python
# Example: Generate exceptions from Jira
import yaml
import jira

# Fetch approved security exceptions from Jira
exceptions = fetch_jira_exceptions(project="SEC")

policy = load_policy("base.yaml")
policy['exceptions'] = exceptions
save_policy("dynamic.yaml", policy)
```

### Custom Reporting
Process JSON output for custom dashboards:
```bash
# Export to JSON
cipherrun example.com --policy policy.yaml --policy-format json > results.json

# Process with jq
jq '.violations[] | select(.action == "Fail")' results.json

# Import into monitoring system
curl -X POST https://monitoring.example.com/api/policy-results \
  -d @results.json
```

### Batch Policy Enforcement
```bash
# Scan multiple targets with same policy
while read target; do
  cipherrun "$target" --policy production.yaml --enforce
done < targets.txt
```

## References

- **PCI-DSS v4.0**: [https://www.pcisecuritystandards.org/](https://www.pcisecuritystandards.org/)
- **NIST SP 800-52r2**: [https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- **SSL Labs Grading**: [https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)

## Support

For issues, feature requests, or questions:
- GitHub Issues: [https://github.com/seifreed/cipherrun/issues](https://github.com/seifreed/cipherrun/issues)
- Documentation: [https://github.com/seifreed/cipherrun](https://github.com/seifreed/cipherrun)
