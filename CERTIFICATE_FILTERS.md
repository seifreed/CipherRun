# Certificate Validation Filters

CipherRun now supports certificate validation filters similar to tlsx, allowing you to quickly identify problematic certificates without parsing full scan output.

## Overview

Certificate filters allow you to focus on specific certificate validation issues by showing only hosts that match the specified criteria. This is particularly useful when scanning large numbers of targets to identify security issues.

## Available Filters

### 1. Expired Certificates (`--expired` / `-x`)

Display only hosts with expired certificates.

```bash
# Find all hosts with expired certificates
cipherrun --file domains.txt --expired

# Short form
cipherrun -f domains.txt -x
```

**Detection Criteria:**
- Certificate `notAfter` date is in the past
- Validation result contains `Expired` issue
- `not_expired` flag is false

### 2. Self-Signed Certificates (`--self-signed` / `-s`)

Display only hosts with self-signed certificates.

```bash
# Find self-signed certificates
cipherrun --file domains.txt --self-signed

# Short form
cipherrun -f domains.txt -s
```

**Detection Criteria:**
- Certificate subject equals issuer (subject == issuer)
- Validation result contains `SelfSigned` issue
- Certificate is not in known root CA stores

### 3. Hostname Mismatched Certificates (`--mismatched` / `-m`)

Display only hosts where the certificate hostname doesn't match the requested hostname.

```bash
# Find hostname mismatches
cipherrun --file domains.txt --mismatched

# Short form
cipherrun -f domains.txt -m
```

**Detection Criteria:**
- Hostname not found in Subject Alternative Names (SANs)
- Hostname doesn't match Common Name (CN)
- Wildcard certificates that don't match the hostname
- Validation result contains `HostnameMismatch` issue

### 4. Revoked Certificates (`--revoked` / `-r`)

Display only hosts with revoked certificates (requires `--phone-out` for OCSP/CRL checks).

```bash
# Find revoked certificates (with revocation checking enabled)
cipherrun --file domains.txt --revoked --phone-out

# Short form
cipherrun -f domains.txt -r --phone-out
```

**Detection Criteria:**
- OCSP status reports certificate as revoked
- CRL check shows certificate is revoked
- Revocation status is `Revoked`

**Note:** Requires `--phone-out` flag to enable actual OCSP/CRL checking.

### 5. Untrusted Certificates (`--untrusted` / `-u`)

Display only hosts with certificates that aren't trusted by major certificate authorities.

```bash
# Find untrusted certificates
cipherrun --file domains.txt --untrusted

# Short form
cipherrun -f domains.txt -u
```

**Detection Criteria:**
- Certificate chain doesn't validate to a known root CA
- Root CA not found in Mozilla, Apple, Android, Java, or Windows trust stores
- Validation result contains `UntrustedCA` issue
- Platform trust validation fails across all platforms

## Filter Logic

### OR Logic (Any Match)

Multiple filters use **OR logic** - a certificate is displayed if it matches **ANY** of the specified filters.

```bash
# Show certificates that are EITHER expired OR self-signed OR both
cipherrun -f domains.txt --expired --self-signed

# This will show:
# - Certificates that are expired (even if not self-signed)
# - Certificates that are self-signed (even if not expired)
# - Certificates that are both expired and self-signed
```

### No Filters = Show All

When no filters are specified, all scan results are displayed regardless of certificate status.

```bash
# Shows all results (default behavior)
cipherrun -f domains.txt
```

## Usage Examples

### Find All Expired Certificates

```bash
cipherrun --file targets.txt --expired
```

Output:
```
ℹ Applied certificate filters: expired
ℹ Showing 5 of 100 targets that match filter criteria

MASS SCAN SUMMARY
================================================================================

Total: 100 | Successful: 5 | Failed: 0

Individual Results:
--------------------------------------------------------------------------------
expired1.example.com:443         | Grade: F    | Cert: ✗ | Vulns: 0
expired2.example.com:443         | Grade: F    | Cert: ✗ | Vulns: 0
expired3.example.com:443         | Grade: F    | Cert: ✗ | Vulns: 1
expired4.example.com:443         | Grade: C    | Cert: ✗ | Vulns: 0
expired5.example.com:443         | Grade: F    | Cert: ✗ | Vulns: 2
```

### Find Self-Signed or Untrusted Certificates

```bash
cipherrun -f internal-services.txt --self-signed --untrusted --json results.json
```

This will:
1. Scan all targets in `internal-services.txt`
2. Filter results to show only self-signed OR untrusted certificates
3. Export filtered results to `results.json`

### Identify Hostname Mismatches

```bash
cipherrun -f cdn-endpoints.txt --mismatched
```

Useful for finding:
- Incorrectly configured CDN certificates
- Shared hosting certificate issues
- Multi-domain certificate problems

### Security Audit: Find All Certificate Issues

```bash
# Find any certificate with validation problems
cipherrun -f domains.txt \
  --expired \
  --self-signed \
  --mismatched \
  --untrusted \
  --revoked \
  --phone-out \
  --json certificate-issues.json
```

## Integration with Output Formats

Filters work with all output formats:

### JSON Output
```bash
cipherrun -f targets.txt --expired --json expired-certs.json --json-pretty
```

Only expired certificates will be included in the JSON output.

### CSV Output
```bash
cipherrun -f targets.txt --self-signed --csv self-signed.csv
```

### Terminal Output
```bash
# Default terminal output with filters
cipherrun -f targets.txt --mismatched
```

## Practical Use Cases

### 1. Pre-Expiration Audit

Find certificates that are expired (should be zero in production):

```bash
cipherrun -f production-domains.txt --expired
```

### 2. Internal Certificate Discovery

Find self-signed certificates in internal infrastructure:

```bash
cipherrun -f internal-ips.txt --self-signed
```

### 3. CDN Migration Verification

Verify all domains have correct certificates after CDN migration:

```bash
cipherrun -f migrated-domains.txt --mismatched
```

If any results appear, those domains need certificate fixes.

### 4. Security Compliance Check

Find any non-compliant certificates:

```bash
cipherrun -f all-domains.txt \
  --expired \
  --untrusted \
  --revoked \
  --phone-out
```

### 5. Development Environment Cleanup

Find and document self-signed certificates in dev/test environments:

```bash
cipherrun -f dev-services.txt --self-signed --csv dev-self-signed.csv
```

## Performance Considerations

### Filter After Scan

Filters are applied **after** scanning completes, not during the scan. This means:

- All targets are scanned normally
- Certificate validation is performed for all targets
- Results are filtered based on certificate status before display

### Use Case: Quick Issue Identification

When scanning hundreds of targets, filters help you quickly identify problems:

```bash
# Scan 1000 domains, show only the problematic ones
cipherrun -f 1000-domains.txt --expired --untrusted
```

Instead of reviewing 1000 results, you see only the targets that need attention.

## Combining with Other Features

### With Policy Enforcement

```bash
# Find expired certificates and check against security policy
cipherrun -f domains.txt --expired --policy security-policy.yaml --enforce
```

### With Compliance Frameworks

```bash
# Find certificate issues and generate PCI-DSS compliance report
cipherrun -f payment-gateways.txt \
  --expired \
  --untrusted \
  --compliance pci-dss-v4 \
  --compliance-format html
```

### With Parallel Scanning

```bash
# Fast parallel scan with filtering
cipherrun -f large-domain-list.txt \
  --expired \
  --parallel \
  --max-parallel 50
```

## Filter Status Messages

When filters are active, CipherRun displays helpful status messages:

```
ℹ Applied certificate filters: expired, self-signed
ℹ Showing 12 of 200 targets that match filter criteria
```

This helps you understand:
- Which filters are active
- How many results matched vs. total scanned
- That filtering was successfully applied

## Troubleshooting

### No Results When Expecting Some

If you get zero results when filters are active:

1. **Verify filter flags**: Ensure you're using the correct flag names
2. **Check certificate validation**: Run without filters first to see all results
3. **Enable verbose mode**: Use `-v` for detailed validation output

```bash
# Debug why no expired certificates are found
cipherrun -f domains.txt --expired -v
```

### Revoked Filter Returns Nothing

The `--revoked` filter requires actual OCSP/CRL checking:

```bash
# WRONG: No revocation checks performed
cipherrun -f domains.txt --revoked

# CORRECT: Enable phone-out for OCSP/CRL
cipherrun -f domains.txt --revoked --phone-out
```

### Filter Not Applied to Output

Ensure you're using the filtered results in output:

```bash
# Results are filtered before export
cipherrun -f domains.txt --expired --json filtered.json
```

The JSON file will contain only filtered results, not all scan results.

## API

When using CipherRun as a library, you can use the filtering functionality programmatically:

```rust
use cipherrun::certificates::status::CertificateStatus;
use cipherrun::cli::Args;

// Create certificate status from validation result
let cert_status = CertificateStatus::from_validation_result(
    &validation,
    hostname,
    &cert,
    revocation.as_ref(),
);

// Check if status matches filters
let mut args = Args::default();
args.filter_expired = true;
args.filter_self_signed = true;

if cert_status.matches_filter(&args) {
    // Certificate matches filter criteria
    println!("Certificate has issues: {}", hostname);
}
```

## Summary

Certificate validation filters provide a powerful way to:
- Quickly identify certificate issues across many targets
- Focus on specific validation problems
- Integrate certificate monitoring into CI/CD pipelines
- Generate filtered reports for security audits
- Reduce noise when scanning large environments

All filters use OR logic, work with all output formats, and integrate seamlessly with CipherRun's other features like parallel scanning, policy enforcement, and compliance checking.
