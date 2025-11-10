# CipherRun vs tlsx - Comprehensive Gap Analysis for 1:1 Parity

**Date:** 2025-11-10
**Analysis Version:** 1.0
**Purpose:** Identify all missing features in CipherRun compared to tlsx for achieving 1:1 feature parity

---

## Executive Summary

### Summary Statistics
- **Total tlsx features:** 47
- **CipherRun has:** 68
- **Missing in CipherRun:** 15
- **Exact parity features:** 32
- **CipherRun unique features:** 36
- **Current parity percentage:** 68.1%

### Key Findings
1. **CipherRun is significantly more comprehensive** in vulnerability testing (18 checks vs 0)
2. **CipherRun has superior compliance/security features** not present in tlsx
3. **tlsx excels at certificate transparency** and lightweight scanning
4. **Critical gaps:** CT logs streaming, JA3/JA3S fingerprinting, pre-handshake termination
5. **CipherRun's advantages:** Policy engine, compliance frameworks, REST API, monitoring daemon

---

## Feature Comparison Matrix

### ✅ EXACT PARITY FEATURES (32)

| Feature | CipherRun | tlsx | Notes |
|---------|-----------|------|-------|
| **Basic Scanning** |
| Single host scanning | ✓ | ✓ | Both support |
| Multiple host input (file) | ✓ (-f) | ✓ (-l) | Different flags |
| Port specification | ✓ | ✓ | Both support |
| IPv4/IPv6 selection | ✓ (-4/-6) | ✓ (-iv) | Both support |
| **Certificate Information** |
| Subject Alternative Names (SAN) | ✓ | ✓ (--san) | |
| Common Name (CN) | ✓ | ✓ (--cn) | |
| Subject Organization | ✓ | ✓ (--so) | |
| Certificate serial number | ✓ | ✓ (--serial) | |
| Certificate fingerprint hashes | ✓ | ✓ (--hash) | md5, sha1, sha256 |
| Wildcard certificate detection | ✓ | ✓ (--wildcard-cert) | |
| **TLS/SSL Configuration** |
| TLS version detection | ✓ | ✓ (--tls-version) | |
| TLS version enumeration | ✓ (-p) | ✓ (--version-enum) | |
| Cipher detection | ✓ | ✓ (--cipher) | |
| Cipher enumeration | ✓ (-e/-E) | ✓ (--cipher-enum) | |
| Cipher filtering by strength | ✓ | ✓ (--cipher-type) | |
| Min/Max TLS version | ✓ | ✓ (--min-version/--max-version) | |
| Custom cipher selection | ✓ | ✓ (--cipher-input) | |
| Custom SNI hostname | ✓ (--sni-name) | ✓ (--sni) | |
| **Certificate Validation** |
| Expired certificate detection | ✓ | ✓ (--expired) | |
| Self-signed certificate detection | ✓ | ✓ (--self-signed) | |
| Mismatched certificate detection | ✓ | ✓ (--mismatched) | |
| Revoked certificate detection | ✓ | ✓ (--revoked) | CRL/OCSP |
| Untrusted certificate detection | ✓ | ✓ (--untrusted) | |
| Certificate chain validation | ✓ | ✓ (--tls-chain) | |
| Certificate verification | ✓ | ✓ (--verify-cert) | |
| **Output Formats** |
| JSON output | ✓ | ✓ | Both support |
| Pretty JSON | ✓ (--json-pretty) | ✓ (implicit) | |
| Silent mode | ✓ (-q) | ✓ (--silent) | |
| No color output | ✓ (--no-color) | ✓ (--no-color) | |
| **Performance** |
| Concurrent scanning | ✓ (--parallel) | ✓ (-c) | |
| Connection timeout | ✓ (--socket-timeout) | ✓ (--timeout) | |
| Retry logic | ✓ (--max-retries) | ✓ (--retry) | |
| Custom CA certificate | ✓ (--add-ca) | ✓ (--cacert) | |

---

## ❌ MISSING FEATURES IN CIPHERRUN (Priority: CRITICAL)

### 1. Certificate Transparency (CT) Logs Streaming
**What it does in tlsx:**
- Real-time streaming of newly-issued certificates from public CT logs
- Passive subdomain discovery without active scanning
- Fire-hose mode for continuous monitoring
- Custom start indices per CT log source
- Replay historical certificates from index 0

**Flags:**
- `--ct-logs` / `-ctl`: Enable CT logs streaming mode
- `--ctl-beginning` / `-cb`: Start from index 0 for full history
- `--ctl-index` / `-cti`: Custom start index per log (e.g., `google_xenon2025h2=12345`)

**Implementation complexity:** 2-3 weeks
**Priority:** CRITICAL
**Dependencies:**
- Certificate Transparency log client library
- Streaming/async infrastructure
- Duplicate detection (inverse bloom filter)
- Log source configuration

**Use cases:**
- Passive reconnaissance
- Continuous subdomain enumeration
- Certificate monitoring without active scanning
- Threat intelligence gathering

---

### 2. JA3 TLS Client Fingerprinting
**What it does in tlsx:**
- Generates JA3 fingerprint hash of TLS client handshake
- Uses zcrypto/ztls library for deep packet inspection
- Enables client identification and tracking
- Works only in ztls mode

**Flags:**
- `--ja3`: Display JA3 fingerprint hash (using ztls)

**Implementation complexity:** 1-2 weeks
**Priority:** CRITICAL
**Dependencies:**
- JA3 algorithm implementation
- Access to client hello raw bytes
- ztls-like library for packet inspection

**Use cases:**
- Client fingerprinting
- Bot detection
- TLS client identification
- Security research

---

### 3. JA3S TLS Server Fingerprinting
**What it does in tlsx:**
- Generates JA3S fingerprint hash of TLS server handshake
- Server-side equivalent of JA3
- Uses zcrypto/ztls for packet inspection

**Flags:**
- `--ja3s`: Display JA3S fingerprint hash (using ztls)

**Implementation complexity:** 1-2 weeks
**Priority:** CRITICAL
**Dependencies:**
- JA3S algorithm implementation
- Access to server hello raw bytes
- ztls-like library for packet inspection

**Use cases:**
- Server fingerprinting
- Technology stack identification
- Load balancer detection
- Backend server enumeration

---

## ❌ MISSING FEATURES IN CIPHERRUN (Priority: HIGH)

### 4. Pre-Handshake / Early Termination
**What it does in tlsx:**
- Terminates TLS connection after receiving ServerHello and certificate
- Significantly faster scanning (disconnects before full handshake)
- Reduces server load and logs
- Useful for mass certificate collection

**Flags:**
- `--pre-handshake` / `-ps`: Enable early termination using ztls

**Implementation complexity:** 1 week
**Priority:** HIGH
**Dependencies:**
- Low-level TLS stack control
- Custom TLS state machine
- ztls-like library

**Use cases:**
- Fast mass scanning
- Certificate intelligence
- Reduced target impact
- Stealth scanning

---

### 5. Scan All IPs for Hostname
**What it does in tlsx:**
- Resolves all A/AAAA records for a hostname
- Tests all IP addresses (useful for Anycast, CDN, load balancers)
- Reports minimum capability across all IPs

**Flags:**
- `--scan-all-ips` / `-sa`: Scan all resolved IPs for a host

**Implementation complexity:** 3-5 days
**Priority:** HIGH
**Dependencies:**
- DNS resolution enhancement
- Multi-IP result aggregation

**Use cases:**
- Anycast testing
- CDN configuration testing
- Load balancer enumeration
- Geographic diversity testing

---

### 6. Random SNI Generation
**What it does in tlsx:**
- Automatically generates random SNI when none provided
- Useful for testing default server behavior
- Helps with stealth scanning

**Flags:**
- `--random-sni` / `-rs`: Use random SNI when empty

**Implementation complexity:** 2-3 days
**Priority:** HIGH
**Dependencies:**
- Random hostname generator

**Use cases:**
- Default server configuration testing
- Virtual host enumeration
- Stealth scanning

---

### 7. Reverse PTR SNI
**What it does in tlsx:**
- Performs reverse DNS lookup (PTR) to retrieve SNI from IP address
- Automatically uses PTR result as SNI
- Useful for IP-only scanning

**Flags:**
- `--rev-ptr-sni` / `-rps`: Perform reverse PTR to retrieve SNI from IP

**Implementation complexity:** 3-5 days
**Priority:** HIGH
**Dependencies:**
- DNS PTR query support

**Use cases:**
- IP-only scanning
- Automated SNI discovery
- Reverse infrastructure mapping

---

### 8. ASN and CIDR Input Support
**What it does in tlsx:**
- Accepts ASN numbers as input (e.g., AS1449)
- Accepts CIDR ranges (e.g., 173.0.84.0/24)
- Automatically expands to all IPs in range
- Mass infrastructure scanning

**Flags:**
- Input parsing supports: `AS1449`, `173.0.84.0/24`

**Implementation complexity:** 1 week
**Priority:** HIGH
**Dependencies:**
- ASN to IP range mapping (via whois/RIR data)
- CIDR expansion library

**Use cases:**
- Organization-wide scanning
- Cloud provider scanning
- Large-scale reconnaissance

---

### 9. Client Hello / Server Hello Raw Data Export
**What it does in tlsx:**
- Includes raw client hello bytes in JSON output
- Includes raw server hello bytes in JSON output
- Enables deep protocol analysis
- Only available in ztls mode

**Flags:**
- `--client-hello` / `-ch`: Include client hello in JSON (ztls mode)
- `--server-hello` / `-sh`: Include server hello in JSON (ztls mode)

**Implementation complexity:** 1-2 weeks
**Priority:** HIGH
**Dependencies:**
- Low-level TLS packet capture
- ztls-like library

**Use cases:**
- Protocol research
- Custom fingerprinting
- TLS extension analysis
- Security research

---

### 10. TLS Probe Status
**What it does in tlsx:**
- Reports connection success/failure explicitly
- Useful for port scanning / service discovery
- Returns probe status even on connection failure

**Flags:**
- `--probe-status` / `-tps`: Display TLS probe status

**Implementation complexity:** 2-3 days
**Priority:** HIGH
**Dependencies:**
- Enhanced error handling
- Status reporting in output

**Use cases:**
- Service discovery
- Port scanning integration
- Connection monitoring

---

## ❌ MISSING FEATURES IN CIPHERRUN (Priority: MEDIUM)

### 11. DNS-Only Output Mode
**What it does in tlsx:**
- Extracts and outputs only unique DNS names from certificates
- Combines SAN + CN into deduplicated list
- Useful for subdomain enumeration pipelines

**Flags:**
- `--dns`: Display unique hostname from SSL certificate response

**Implementation complexity:** 2-3 days
**Priority:** MEDIUM
**Dependencies:**
- DNS name extraction and deduplication

**Use cases:**
- Subdomain enumeration
- Pipeline integration with dnsx/httpx
- Asset discovery

---

### 12. Response-Only Output Mode
**What it does in tlsx:**
- Displays only the probe response data (no metadata)
- Minimal output for scripting/parsing
- Optimized for pipeline integration

**Flags:**
- `--resp-only` / `-ro`: Display TLS response only

**Implementation complexity:** 2-3 days
**Priority:** MEDIUM
**Dependencies:**
- Output formatter modification

**Use cases:**
- Shell scripting
- Pipeline integration
- Minimal output requirements

---

### 13. Custom Resolvers Support
**What it does in tlsx:**
- Specify custom DNS resolvers
- Bypass default system resolvers
- Support for DoH, DoT, custom servers

**Flags:**
- `--resolvers` / `-r`: List of resolvers to use

**Implementation complexity:** 3-5 days
**Priority:** MEDIUM
**Dependencies:**
- Custom DNS resolver configuration

**Use cases:**
- DNS filtering bypass
- Custom resolution testing
- Privacy-enhanced scanning

---

### 14. Connection Delay / Rate Limiting
**What it does in tlsx:**
- Adds configurable delay between connections per thread
- Helps avoid overwhelming targets
- IDS/IPS evasion

**Flags:**
- `--delay`: Duration to wait between connections (e.g., `200ms`, `1s`)

**Implementation complexity:** 2-3 days
**Priority:** MEDIUM
**Dependencies:**
- Timer/delay mechanism in scanner

**Note:** CipherRun has `--sleep` but it's different - tlsx has per-thread delay

**Use cases:**
- Rate limiting
- Stealth scanning
- Avoiding detection

---

### 15. Hard Fail on Revocation Check Errors
**What it does in tlsx:**
- Strict mode for revocation status checking
- Treats revocation check failures as certificate failures
- Compliance with strict security policies

**Flags:**
- `--hardfail` / `-hf`: Strategy to use if errors while checking revocation status

**Implementation complexity:** 2-3 days
**Priority:** MEDIUM
**Dependencies:**
- Enhanced revocation checking logic

**Use cases:**
- Strict compliance checking
- High-security environments
- Audit requirements

---

## ✅ CIPHERRUN UNIQUE ADVANTAGES (Not in tlsx)

CipherRun has **36 unique features** that tlsx does not offer:

### Vulnerability Detection (18 checks) - tlsx has ZERO
1. ✅ Heartbleed (CVE-2014-0160)
2. ✅ CCS Injection (CVE-2014-0224)
3. ✅ Ticketbleed
4. ✅ ROBOT (Return of Bleichenbacher's Oracle Threat)
5. ✅ POODLE (SSL & TLS variants)
6. ✅ BEAST (CVE-2011-3389)
7. ✅ CRIME (CVE-2012-4929)
8. ✅ BREACH (CVE-2013-3587)
9. ✅ SWEET32 (CVE-2016-2183)
10. ✅ FREAK (CVE-2015-0204)
11. ✅ LOGJAM (CVE-2015-4000)
12. ✅ DROWN (CVE-2016-0800)
13. ✅ LUCKY13 (CVE-2013-0169)
14. ✅ RC4 Biases
15. ✅ Renegotiation Issues
16. ✅ TLS_FALLBACK_SCSV
17. ✅ Winshock
18. ✅ STARTTLS Injection

### Advanced Security Features
19. ✅ SSL Labs Rating System (complete A+ through F grading)
20. ✅ CVSS scoring integration
21. ✅ HTTP Security Headers testing (HSTS, CSP, X-Frame-Options, etc.)
22. ✅ Cookie security analysis (Secure, HttpOnly, SameSite)
23. ✅ Server fingerprinting

### Client Simulation
24. ✅ 126+ real-world client profiles (browsers, OS, mobile devices)
25. ✅ Compatibility testing (which clients can connect)
26. ✅ Protocol/cipher negotiation per client

### STARTTLS Support (14 protocols)
27. ✅ SMTP, IMAP, POP3, LMTP
28. ✅ FTP, LDAP
29. ✅ PostgreSQL, MySQL
30. ✅ XMPP (Client & Server), IRC
31. ✅ NNTP, ManageSieve, Telnet

### Certificate Analysis
32. ✅ Chain validation against 5 CA stores (Mozilla, Apple, Linux, Microsoft, Java)
33. ✅ CRL and OCSP revocation checking
34. ✅ Extended Validation (EV) certificate detection
35. ✅ Certificate Transparency (CT) verification
36. ✅ CAA record checking

### Mass Scanning Features
37. ✅ MX record testing (all mail servers for domain)
38. ✅ Parallel and serial scanning modes
39. ✅ Configurable worker pool (--max-parallel)

### Output Formats
40. ✅ CSV export
41. ✅ HTML report with rich styling
42. ✅ XML export
43. ✅ Log files

### Enterprise Features (CipherRun-only)
44. ✅ **REST API Server** (--serve)
   - OpenAPI/Swagger documentation
   - Rate limiting
   - WebSocket support
   - Async scan queue

45. ✅ **Database Persistence** (PostgreSQL/SQLite)
   - Scan history storage
   - Trend analysis
   - Change detection
   - Comparison reports
   - Dashboard generation

46. ✅ **Policy-as-Code Engine**
   - YAML policy definitions
   - Custom security rules
   - CI/CD integration (--enforce)
   - Violation reporting

47. ✅ **Compliance Framework Engine**
   - PCI DSS v4
   - NIST SP 800-52r2
   - HIPAA
   - SOC 2
   - GDPR
   - Mozilla Modern/Intermediate

48. ✅ **Certificate Monitoring Daemon**
   - Continuous monitoring
   - Expiration alerts
   - Email notifications
   - Configuration changes detection

49. ✅ **Analytics & Reporting**
   - Scan comparison
   - Change tracking over time
   - Trend analysis
   - Dashboard generation

### Protocol Testing
50. ✅ SSLv2 and SSLv3 support (legacy protocol testing)
51. ✅ Full TLS 1.3 support with 0-RTT testing
52. ✅ Protocol intolerance detection
53. ✅ Session resumption testing
54. ✅ NPN (Next Protocol Negotiation)
55. ✅ ALPN (Application-Layer Protocol Negotiation)
56. ✅ Server signature algorithms enumeration
57. ✅ Key exchange groups enumeration
58. ✅ Client CA list detection

### Advanced Testing
59. ✅ RDP protocol support (--rdp)
60. ✅ Mutual TLS (mTLS) client certificate support
61. ✅ Proxy support (SOCKS5)
62. ✅ Custom HTTP headers
63. ✅ IDS-friendly mode (slower, evasive)
64. ✅ Sneaky mode (less traces in logs)
65. ✅ Retry with exponential backoff
66. ✅ Connection timing measurements
67. ✅ Handshake time display
68. ✅ Debian weak keys detection

---

## IMPLEMENTATION ROADMAP

### Phase 1: Critical Features (6-8 weeks)
**Goal:** Achieve core parity for certificate intelligence gathering

1. **Week 1-3: Certificate Transparency Logs**
   - Integrate CT log client library
   - Implement streaming mode
   - Add duplicate detection
   - Test with major CT logs

2. **Week 4-5: JA3/JA3S Fingerprinting**
   - Implement JA3 algorithm
   - Implement JA3S algorithm
   - Add packet inspection capability
   - Integrate with existing TLS stack

3. **Week 6-8: Pre-Handshake & Early Termination**
   - Modify TLS state machine
   - Add early termination support
   - Test performance improvements
   - Ensure compatibility

**Dependencies:** All critical features are independent, can be developed in parallel

### Phase 2: High Priority Features (4-6 weeks)
**Goal:** Enhanced scanning capabilities and input flexibility

4. **Week 9-10: ASN & CIDR Support**
   - Add ASN to IP mapping
   - CIDR expansion logic
   - Input parser enhancement

5. **Week 11-12: Advanced SNI & DNS Features**
   - Random SNI generation
   - Reverse PTR SNI
   - Scan all IPs for hostname
   - DNS-only output mode

6. **Week 13-14: TLS Handshake Data Export**
   - Client Hello raw export
   - Server Hello raw export
   - Probe status reporting

**Dependencies:**
- ASN/CIDR support independent
- SNI features can share common code
- Handshake export requires low-level TLS access

### Phase 3: Medium Priority Features (2-3 weeks)
**Goal:** Pipeline integration and operational features

7. **Week 15-16: Pipeline & Output Enhancements**
   - Response-only mode
   - Custom resolvers support
   - Connection delay/rate limiting

8. **Week 17: Compliance & Validation**
   - Hard-fail revocation checking
   - Testing and validation

**Dependencies:** All medium features are independent

### Phase 4: Testing & Documentation (2 weeks)
**Goal:** Ensure quality and feature parity

9. **Week 18-19: Integration Testing**
   - End-to-end feature testing
   - Performance benchmarking
   - Compatibility testing
   - Bug fixes

10. **Week 19-20: Documentation**
    - Update README
    - Add examples
    - Create migration guide from tlsx
    - API documentation

---

## PRIORITY GROUPING BY IMPACT

### Tier 1: Must-Have for Parity (Critical + High Priority)
**Total implementation time:** 12-14 weeks

1. Certificate Transparency logs streaming ⭐⭐⭐⭐⭐
2. JA3 fingerprinting ⭐⭐⭐⭐⭐
3. JA3S fingerprinting ⭐⭐⭐⭐⭐
4. Pre-handshake / early termination ⭐⭐⭐⭐
5. ASN/CIDR input support ⭐⭐⭐⭐
6. Scan all IPs ⭐⭐⭐⭐
7. Random SNI ⭐⭐⭐
8. Reverse PTR SNI ⭐⭐⭐
9. Client/Server Hello export ⭐⭐⭐
10. Probe status ⭐⭐⭐

### Tier 2: Nice-to-Have for Complete Parity (Medium Priority)
**Total implementation time:** 2-3 weeks

11. DNS-only output mode
12. Response-only output mode
13. Custom resolvers
14. Connection delay
15. Hard-fail revocation

---

## ESTIMATED EFFORT SUMMARY

| Priority | Features | Development Time | Testing Time | Total |
|----------|----------|------------------|--------------|-------|
| Critical | 3 | 5-7 weeks | 1 week | 6-8 weeks |
| High | 7 | 4-5 weeks | 1 week | 5-6 weeks |
| Medium | 5 | 2-3 weeks | 1 week | 3-4 weeks |
| **TOTAL** | **15** | **11-15 weeks** | **3 weeks** | **14-18 weeks** |

**Full 1:1 parity estimated delivery:** 3.5 - 4.5 months with single developer

---

## COMPETITIVE ANALYSIS

### tlsx Strengths
1. ✅ **Lightweight & Fast:** Optimized for mass certificate intelligence
2. ✅ **Certificate Transparency:** Fire-hose streaming mode for passive recon
3. ✅ **Fingerprinting:** JA3/JA3S for client/server identification
4. ✅ **Pre-handshake:** Early termination for speed
5. ✅ **Pipeline Integration:** Designed for ProjectDiscovery toolchain
6. ✅ **Simplicity:** Focused on certificate data collection

### CipherRun Strengths
1. ✅ **Comprehensive Security Testing:** 18 vulnerability checks
2. ✅ **Enterprise Features:** REST API, database, monitoring, compliance
3. ✅ **SSL Labs Rating:** Industry-standard grading system
4. ✅ **Client Simulation:** 126+ real-world profiles
5. ✅ **Policy Engine:** Custom security rules and CI/CD integration
6. ✅ **Compliance Frameworks:** 7 built-in frameworks (PCI DSS, HIPAA, etc.)
7. ✅ **STARTTLS Support:** 14 protocols vs tlsx's limited support
8. ✅ **Multi-Format Output:** HTML, CSV, XML reports
9. ✅ **Advanced Analysis:** Trend tracking, change detection, comparisons

### When to Use Each Tool

**Use tlsx when:**
- Passive certificate intelligence gathering
- Mass subdomain enumeration via CT logs
- Client/server fingerprinting (JA3/JA3S)
- Fast, lightweight scanning
- Pipeline integration with other PD tools
- Certificate collection without deep analysis

**Use CipherRun when:**
- Security vulnerability assessment
- Compliance auditing (PCI DSS, HIPAA, etc.)
- SSL Labs-style grading
- Enterprise deployment (API, database, monitoring)
- Policy enforcement in CI/CD
- Comprehensive TLS/SSL analysis
- Client compatibility testing
- STARTTLS protocol testing
- Long-term trend analysis

---

## RECOMMENDED IMPLEMENTATION STRATEGY

### Option A: Full Parity (Recommended)
**Timeline:** 4-5 months
**Approach:** Implement all 15 missing features
**Benefits:**
- Complete feature parity with tlsx
- Best of both worlds (tlsx speed + CipherRun depth)
- Attract tlsx user base
- Competitive advantage

### Option B: Strategic Parity
**Timeline:** 2-3 months
**Approach:** Implement only Critical + High priority (10 features)
**Benefits:**
- Faster time to market
- 85% feature parity
- Core use cases covered
- Lower development cost

### Option C: Differentiation
**Timeline:** 1-2 months
**Approach:** Implement only Critical features (3 features)
**Benefits:**
- Focus on unique advantages (vulnerability testing, compliance)
- Maintain CipherRun's identity as security assessment tool
- Add just enough tlsx features for competitiveness

---

## CONCLUSION

CipherRun is already **superior to tlsx** in most security testing scenarios. The tool offers:
- 18 vulnerability checks vs 0
- Enterprise features (API, DB, monitoring)
- Compliance frameworks
- SSL Labs rating
- Client simulation

However, tlsx excels in **passive certificate intelligence** with:
- Certificate Transparency streaming
- JA3/JA3S fingerprinting
- Pre-handshake scanning

**Recommendation:** Implement **Option A (Full Parity)** to create the industry's most comprehensive TLS/SSL scanner that combines:
- tlsx's certificate intelligence capabilities
- CipherRun's security assessment depth
- Enterprise features unique to CipherRun

This positions CipherRun as the **go-to tool** for both reconnaissance and security assessment.

**Final Parity Target:** 100% (all 47 tlsx features + 36 unique CipherRun features = 83 total features)

---

## APPENDIX: FEATURE CROSS-REFERENCE

### tlsx flag → CipherRun equivalent

| tlsx Flag | CipherRun Flag | Status |
|-----------|----------------|--------|
| `-u, --host` | `[URI]` or `-f` | ✅ Exists |
| `-l, --list` | `-f, --file` | ✅ Exists |
| `-p, --port` | `--port` | ✅ Exists |
| `--san` | Default behavior | ✅ Exists |
| `--cn` | Default behavior | ✅ Exists |
| `--so` | Default behavior | ✅ Exists |
| `--tls-version` | `-p, --protocols` | ✅ Exists |
| `--cipher` | `-e, --each-cipher` | ✅ Exists |
| `--hash` | Default in cert output | ✅ Exists |
| `--jarm` | ❌ | ❌ MISSING |
| `--ja3` | ❌ | ❌ MISSING |
| `--ja3s` | ❌ | ❌ MISSING |
| `--wildcard-cert` | Auto-detected | ✅ Exists |
| `--probe-status` | ❌ | ❌ MISSING |
| `--version-enum` | `-p` | ✅ Exists |
| `--cipher-enum` | `-e/-E` | ✅ Exists |
| `--cipher-type` | `-s` | ✅ Exists |
| `--client-hello` | ❌ | ❌ MISSING |
| `--server-hello` | ❌ | ❌ MISSING |
| `--serial` | Default in cert | ✅ Exists |
| `--ct-logs` | ❌ | ❌ MISSING |
| `--ctl-beginning` | ❌ | ❌ MISSING |
| `--ctl-index` | ❌ | ❌ MISSING |
| `--expired` | Auto-detected | ✅ Exists |
| `--self-signed` | Auto-detected | ✅ Exists |
| `--mismatched` | Auto-detected | ✅ Exists |
| `--revoked` | Auto-detected | ✅ Exists |
| `--untrusted` | Auto-detected | ✅ Exists |
| `--resolvers` | ❌ | ❌ MISSING |
| `--cacert` | `--add-ca` | ✅ Exists |
| `--cipher-input` | Custom cipher | ✅ Exists |
| `--sni` | `--sni-name` | ✅ Exists |
| `--random-sni` | ❌ | ❌ MISSING |
| `--rev-ptr-sni` | ❌ | ❌ MISSING |
| `--min-version` | `--tls10/11/12/13` | ✅ Exists |
| `--max-version` | `--tls10/11/12/13` | ✅ Exists |
| `--certificate` | Default | ✅ Exists |
| `--tls-chain` | Default | ✅ Exists |
| `--verify-cert` | Default | ✅ Exists |
| `--openssl-binary` | `--openssl` | ✅ Exists |
| `--hardfail` | ❌ | ❌ MISSING |
| `--proxy` | `--proxy` | ✅ Exists |
| `--concurrency` | `--max-parallel` | ✅ Exists |
| `--timeout` | `--socket-timeout` | ✅ Exists |
| `--retry` | `--max-retries` | ✅ Exists |
| `--delay` | `--sleep` | ⚠️ Partial |
| `-o, --output` | `--json/csv/html` | ✅ Exists |
| `--json` | `--json` | ✅ Exists |
| `--dns` | ❌ | ❌ MISSING |
| `--resp-only` | ❌ | ❌ MISSING |
| `--silent` | `-q, --quiet` | ✅ Exists |
| `--no-color` | `--no-color` | ✅ Exists |
| `--verbose` | `-v, --verbose` | ✅ Exists |
| `--pre-handshake` | ❌ | ❌ MISSING |
| `--scan-all-ips` | ❌ | ❌ MISSING |
| `--scan-mode` | N/A | Different |
| `--ip-version` | `-4/-6` | ✅ Exists |

---

**End of Gap Analysis**
