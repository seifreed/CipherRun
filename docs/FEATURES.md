# CipherRun Features

Comprehensive documentation of CipherRun's features and capabilities.

## Table of Contents

- [Protocol Support](#protocol-support)
- [Cipher Suite Analysis](#cipher-suite-analysis)
- [Vulnerability Detection](#vulnerability-detection)
- [Certificate Analysis](#certificate-analysis)
- [HTTP Security Headers](#http-security-headers)
- [Client Simulation](#client-simulation)
- [SSL Labs Rating](#ssl-labs-rating)
- [STARTTLS Support](#starttls-support)
- [Output Formats](#output-formats)
- [Mass Scanning](#mass-scanning)

---

## Protocol Support

### Supported Protocols

CipherRun tests all SSL/TLS protocol versions:

| Protocol | Status | Notes |
|----------|--------|-------|
| SSLv2 | ✅ Supported | Deprecated, tested for compliance |
| SSLv3 | ✅ Supported | Deprecated, POODLE vulnerable |
| TLS 1.0 | ✅ Supported | Deprecated in 2020 |
| TLS 1.1 | ✅ Supported | Deprecated in 2020 |
| TLS 1.2 | ✅ Supported | Current standard |
| TLS 1.3 | ✅ Supported | Latest version, full support |

### TLS 1.3 Features

CipherRun includes complete TLS 1.3 support:

- ✅ **Proper ClientHello construction** with all required extensions
- ✅ **X25519 key exchange** with cryptographically valid keys
- ✅ **10 supported groups** including ffdhe* for DHE
- ✅ **14 signature algorithms** including RSA-PSS variants
- ✅ **Compatible with strict servers** (government, enterprise)
- ✅ **Extension ordering** matches OpenSSL for maximum compatibility

**Tested successfully on**:
- google.com, youtube.com, facebook.com
- github.com, cloudflare.com
- nsa.gov (strict government)
- creand.es (strict enterprise)
- reddit.com (social media)

---

## Cipher Suite Analysis

### Comprehensive Database

- **400+ cipher suites** from all SSL/TLS versions
- **Strength categories**: NULL, Export, Low, Medium, High
- **Security features**: Forward Secrecy (FS), AEAD
- **Per-protocol testing**: Individual cipher tests for each TLS version

### Cipher Strength Classification

| Category | Description | Security Level |
|----------|-------------|----------------|
| **NULL** | No encryption | ❌ Insecure |
| **Export** | 40-56 bit keys | ❌ Insecure |
| **Low** | < 128 bit | ⚠️ Weak |
| **Medium** | 128 bit | ⚠️ Acceptable |
| **High** | ≥ 256 bit | ✅ Secure |

### Forward Secrecy Detection

Identifies ciphers providing Perfect Forward Secrecy:
- **ECDHE** (Elliptic Curve Diffie-Hellman Ephemeral)
- **DHE** (Diffie-Hellman Ephemeral)

### Testing Modes

```bash
# Test all ciphers
cipherrun -e example.com

# Test ciphers per protocol
cipherrun -E example.com

# Test only forward secrecy ciphers
cipherrun --fs example.com

# Test standard categories
cipherrun -s example.com
```

---

## Vulnerability Detection

### 18 Vulnerability Checks

| Vulnerability | CVE | Severity | Description |
|--------------|-----|----------|-------------|
| **Heartbleed** | CVE-2014-0160 | Critical | OpenSSL memory leak |
| **CCS Injection** | CVE-2014-0224 | Critical | Cipher suite injection |
| **Ticketbleed** | CVE-2016-9244 | High | Session ticket memory leak |
| **ROBOT** | CVE-2017-13098 | High | RSA padding oracle |
| **POODLE (SSL)** | CVE-2014-3566 | High | SSLv3 padding oracle |
| **POODLE (TLS)** | CVE-2014-8730 | Medium | TLS 1.0-1.2 variant |
| **BEAST** | CVE-2011-3389 | Medium | CBC cipher attack |
| **CRIME** | CVE-2012-4929 | Medium | Compression attack |
| **BREACH** | CVE-2013-3587 | Medium | HTTP compression attack |
| **SWEET32** | CVE-2016-2183 | Low | 64-bit block cipher |
| **FREAK** | CVE-2015-0204 | High | Export cipher downgrade |
| **LOGJAM** | CVE-2015-4000 | High | DHE downgrade |
| **DROWN** | CVE-2016-0800 | High | SSLv2 cross-protocol |
| **LUCKY13** | CVE-2013-0169 | Low | CBC timing attack |
| **RC4 Biases** | Multiple | Medium | RC4 cipher weaknesses |
| **Renegotiation** | CVE-2009-3555 | Medium | TLS renegotiation |
| **TLS_FALLBACK_SCSV** | RFC 7507 | Info | Downgrade protection |
| **Winshock** | MS14-066 | High | Windows Schannel bug |

### Testing Commands

```bash
# Test all vulnerabilities
cipherrun -U example.com

# Test specific vulnerabilities
cipherrun -H example.com          # Heartbleed
cipherrun --robot example.com     # ROBOT
cipherrun -O example.com          # POODLE
cipherrun -B example.com          # BEAST
cipherrun -F example.com          # FREAK
cipherrun -J example.com          # LOGJAM
cipherrun -D example.com          # DROWN
```

---

## Certificate Analysis

### Certificate Validation

CipherRun validates certificates against **5 major CA stores**:

1. **Mozilla** - Firefox/Chrome root store
2. **Apple** - macOS/iOS root store
3. **Linux** - Common Linux distributions
4. **Microsoft** - Windows root store
5. **Java** - JRE cacerts

### Certificate Checks

- ✅ **Hostname verification**: Subject and SAN matching
- ✅ **Validity period**: Not expired, not yet valid
- ✅ **Chain completeness**: Full chain to trusted root
- ✅ **Trust validation**: Against major CA stores
- ✅ **Key strength**: RSA/EC key size analysis
- ✅ **Signature algorithms**: Hash and signature verification
- ✅ **Extended Validation (EV)**: EV certificate detection

### Revocation Checking

- **CRL** (Certificate Revocation Lists)
- **OCSP** (Online Certificate Status Protocol)
- **Must-Staple** detection

### Certificate Information Displayed

```
Subject: CN=example.com, O=Company, C=US
Issuer: CN=CA, O=Certificate Authority
Valid: 2024-01-01 to 2025-01-01
Serial: 1234567890abcdef
Key Size: 2048 bits (RSA)
Signature: sha256WithRSAEncryption
SAN: example.com, www.example.com, api.example.com
```

---

## HTTP Security Headers

### Tested Headers

| Header | Description | Importance |
|--------|-------------|------------|
| **HSTS** | HTTP Strict Transport Security | High |
| **HPKP** | HTTP Public Key Pinning (Deprecated) | Low |
| **CSP** | Content Security Policy | High |
| **X-Frame-Options** | Clickjacking protection | Medium |
| **X-XSS-Protection** | XSS filter control | Low |
| **X-Content-Type-Options** | MIME sniffing protection | Medium |

### Cookie Security

Analyzes cookie security attributes:
- **Secure** flag (HTTPS only)
- **HttpOnly** flag (no JavaScript access)
- **SameSite** attribute (CSRF protection)

### Server Fingerprinting

- Server header analysis
- Version detection
- Banner grabbing

---

## Client Simulation

### 126+ Client Profiles

CipherRun simulates real-world clients to test compatibility:

**Browsers**:
- Chrome (various versions)
- Firefox (various versions)
- Safari (macOS/iOS)
- Edge
- Internet Explorer

**Operating Systems**:
- Windows (7, 8, 10, 11)
- macOS (various versions)
- Linux (various distributions)
- iOS (various versions)
- Android (various versions)

**Other Clients**:
- Java (various versions)
- OpenSSL (various versions)
- curl, wget
- Mobile apps

### Client Simulation Output

For each client, shows:
- ✅ Can connect / ❌ Cannot connect
- Negotiated protocol version
- Negotiated cipher suite
- Warnings about potential issues

---

## SSL Labs Rating

### Complete Implementation

CipherRun implements the full SSL Labs rating methodology:

**Rating Scale**: A+ through F

**Component Scores**:
- **Certificate**: 0-100 (chain, validity, key strength)
- **Protocol Support**: 0-100 (versions, deprecation)
- **Key Exchange**: 0-100 (strength, FS support)
- **Cipher Strength**: 0-100 (algorithm strength)

### Grade Capping Rules

Automatic grade reductions for:
- ❌ **F**: Any critical vulnerability
- ❌ **C**: SSLv3 support
- ❌ **B**: TLS 1.0/1.1 only, or RC4 support
- ⚠️ **Capped at A**: Missing Forward Secrecy
- ✅ **A+**: Perfect configuration + HSTS

---

## STARTTLS Support

### 14 Supported Protocols

| Protocol | Port | Description |
|----------|------|-------------|
| **SMTP** | 25, 587, 465 | Email submission |
| **IMAP** | 143, 993 | Email retrieval |
| **POP3** | 110, 995 | Email retrieval |
| **LMTP** | 24 | Local mail delivery |
| **FTP** | 21 | File transfer |
| **LDAP** | 389, 636 | Directory services |
| **PostgreSQL** | 5432 | Database |
| **MySQL** | 3306 | Database |
| **XMPP Client** | 5222 | Instant messaging |
| **XMPP Server** | 5269 | Server-to-server |
| **IRC** | 6667 | Chat |
| **NNTP** | 119 | Usenet |
| **ManageSieve** | 4190 | Sieve scripts |
| **Telnet** | 23 | Terminal access |

### Usage Examples

```bash
# SMTP
cipherrun -t smtp mail.example.com:587

# IMAP
cipherrun -t imap mail.example.com:143

# PostgreSQL
cipherrun -t postgres db.example.com:5432

# Test all MX records
cipherrun --mx example.com
```

---

## Output Formats

### Terminal Output

- **Colorized**: Easy to read with color coding
- **Formatted**: Clean tables and sections
- **Progress indicators**: Real-time scan progress
- **Summary**: Quick overview at the end

### JSON Output

**Flat JSON** (single line):
```bash
cipherrun --json results.json example.com
```

**Pretty JSON** (formatted):
```bash
cipherrun --json results.json --json-pretty example.com
```

### CSV Output

Spreadsheet-compatible format:
```bash
cipherrun --csv results.csv example.com
```

Perfect for:
- Excel/Google Sheets import
- Data analysis
- Compliance reporting

### HTML Output

Rich, styled HTML reports:
```bash
cipherrun --html report.html example.com
```

Features:
- Professional styling
- Sortable tables
- Color-coded results
- Printable format

---

## Mass Scanning

### Serial Mode

Test targets one at a time:
```bash
cipherrun -f targets.txt
```

### Parallel Mode

Test multiple targets concurrently:
```bash
# Default: 20 concurrent workers
cipherrun -f targets.txt --parallel

# Custom parallelism
cipherrun -f targets.txt --parallel --max-parallel 50
```

### MX Record Testing

Automatically discover and test all mail servers:
```bash
cipherrun --mx example.com
```

This will:
1. Query DNS for MX records
2. Resolve each mail server
3. Test SMTP on port 25
4. Generate comprehensive report

### Performance

On typical hardware:
- **Single scan**: 1-3 seconds (full test suite)
- **Parallel mode**: 100+ hosts per minute
- **Memory**: < 50MB per scan
- **Scales**: With available CPU cores

---

## Best Practices

### Recommended Workflow

1. **Quick scan** first: `cipherrun example.com`
2. **Full analysis** if issues found: `cipherrun -a example.com`
3. **Export results**: Add `--json --csv --html`
4. **Schedule regular scans** for continuous monitoring

### Common Use Cases

**PCI DSS Compliance**:
```bash
cipherrun --json pci_audit.json payment.example.com
```

**Mail Server Audit**:
```bash
cipherrun --mx example.com --json mail_audit.json
```

**API Security**:
```bash
cipherrun -f api_endpoints.txt --parallel --json api_security.json
```

**Continuous Monitoring**:
```bash
# Daily cron job
0 2 * * * cipherrun -f critical_hosts.txt --json /var/reports/daily_scan.json
```

---

## Troubleshooting

### Common Issues

**Connection timeout**:
```bash
# Increase timeout
cipherrun --timeout 30 example.com
```

**IPv6 issues**:
```bash
# Force IPv4
cipherrun -4 example.com
```

**Certificate verification failures**:
- Check system CA certificates
- Verify hostname matches certificate
- Check for expired certificates

### Debug Mode

```bash
# Verbose output
cipherrun -v example.com

# With logging
RUST_LOG=debug cipherrun example.com
```

---

**For more information**:
- [README.md](../README.md) - Main documentation
- [DOCKER.md](DOCKER.md) - Docker testing environment
- [CHANGELOG.md](../CHANGELOG.md) - Version history
