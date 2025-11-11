# CipherRun

**A Fast, Modular, and Scalable TLS/SSL Security Scanner Written in Rust**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Author](https://img.shields.io/badge/Author-@seifreed-green.svg)](https://twitter.com/seifreed)
[![Attribution Required](https://img.shields.io/badge/Attribution-Required-red.svg)](NOTICE)

<a href="https://buymeacoffee.com/seifreed" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

CipherRun is a comprehensive TLS/SSL security scanner written in Rust, designed for superior performance, scalability, and modern security testing capabilities.

**Author**: Marc Rivero ([@seifreed](https://twitter.com/seifreed))

## What Makes CipherRun Unique

Unlike traditional TLS scanners, CipherRun is a **complete enterprise security platform** with:

- **83+ Total Features**: 47 tlsx-compatible features + 36 unique enterprise capabilities
- **18 Vulnerability Tests**: From Heartbleed to ROBOT, all major CVEs covered
- **7 Compliance Frameworks**: PCI-DSS, NIST, HIPAA, SOC 2, Mozilla, GDPR
- **TLS Fingerprinting**: JA3, JA3S, and JARM with signature databases (91+ signatures)
- **Certificate Transparency**: Real-time streaming from 50+ CT logs with Bloom filter deduplication
- **Database Backend**: PostgreSQL/SQLite with time-series analytics and trend analysis
- **24/7 Monitoring**: Certificate monitoring daemon with 5 alert channels
- **Policy-as-Code**: YAML-based security policies with CI/CD integration
- **REST API**: 14 endpoints + WebSocket with OpenAPI/Swagger documentation
- **400+ Cipher Suites**: Comprehensive testing across all TLS versions (SSLv2 to TLS 1.3)
- **126+ Client Simulations**: Real-world browser and application compatibility testing
- **5 CA Trust Stores**: Mozilla, Apple, Linux, Microsoft, Java

## Features

### Protocol Testing
- **All SSL/TLS Protocols**: SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
- **Full TLS 1.3 Support**: Including 0-RTT and modern extensions
- **Legacy Protocol Testing**: Complete SSLv2/SSLv3 support for compliance checks

### Cipher Suite Analysis
- **400+ Cipher Suites**: Comprehensive cipher testing database
- **Per-Protocol Analysis**: Test ciphers for each TLS version
- **Strength Categories**: NULL, Export, Low, Medium, High
- **Forward Secrecy Detection**: ECDHE/DHE cipher identification
- **AEAD Support**: Modern authenticated encryption detection

### Vulnerability Detection (18 Checks)
- **Heartbleed** (CVE-2014-0160)
- **CCS Injection** (CVE-2014-0224)
- **Ticketbleed**
- **ROBOT** (Return of Bleichenbacher's Oracle Threat)
- **POODLE** (SSL & TLS variants)
- **BEAST** (CVE-2011-3389)
- **CRIME** (CVE-2012-4929)
- **BREACH** (CVE-2013-3587)
- **SWEET32** (CVE-2016-2183)
- **FREAK** (CVE-2015-0204)
- **LOGJAM** (CVE-2015-4000)
- **DROWN** (CVE-2016-0800)
- **LUCKY13** (CVE-2013-0169)
- **RC4 Biases**
- **Renegotiation Issues**
- **TLS_FALLBACK_SCSV**
- **Winshock**
- **STARTTLS Injection**

### Certificate Analysis
- **Chain Validation**: Against 5 major CA stores (Mozilla, Apple, Linux, Microsoft, Java)
- **Revocation Checking**: CRL and OCSP support
- **Certificate Details**: Subject, SAN, validity, key strength, signature algorithms
- **Trust Chain Verification**: Complete chain analysis
- **Extended Validation (EV)**: EV certificate detection
- **Certificate Filters**: Filter scan results by validation status (expired, self-signed, mismatched, revoked, untrusted)
  - `--expired` / `-x`: Show only expired certificates
  - `--self-signed` / `-s`: Show only self-signed certificates
  - `--mismatched` / `-m`: Show only hostname mismatches
  - `--revoked` / `-r`: Show only revoked certificates
  - `--untrusted` / `-u`: Show only untrusted certificates

### HTTP Security Headers
- **HSTS** (HTTP Strict Transport Security)
- **HPKP** (HTTP Public Key Pinning) - Deprecated, still checked
- **CSP** (Content Security Policy)
- **X-Frame-Options**, **X-XSS-Protection**, **X-Content-Type-Options**
- **Cookie Security**: Secure, HttpOnly, SameSite flags
- **Server Fingerprinting**: Banner and version detection

### Client Simulation
- **126+ Client Profiles**: Real-world browser and OS handshakes
- **Compatibility Testing**: Determine which clients can connect
- **Protocol & Cipher Negotiation**: See what each client would use

### SSL Labs Rating System
- **Complete Implementation**: Based on SSL Labs Rating Guide
- **Comprehensive Grading**: A+ through F ratings
- **SSL Labs Compatibility Mode**: Aligned with SSL Labs methodology
- **TLS 1.3 Requirement**: Grade A or A+ requires TLS 1.3 support (capped at A- without it)
- **Component Scoring**: Certificate (30%), Protocol (30%), Key Exchange (20%), Cipher (20%)
- **Smart Capping**: Grade limits based on vulnerabilities and weaknesses
- **Instant Failures**: SSLv2, NULL/EXPORT ciphers, expired certificates

### STARTTLS Support (14 Protocols)
- SMTP, IMAP, POP3, LMTP
- FTP, LDAP
- PostgreSQL, MySQL
- XMPP (Client & Server), IRC
- NNTP
- ManageSieve (Sieve)
- Telnet

### Output Formats
- **Terminal**: Colorized, formatted output
- **JSON**: Flat and Pretty variants
- **CSV**: Spreadsheet-compatible
- **HTML**: Rich, styled reports
- **XML**: XML-formatted reports
- **Log Files**: Complete session logs

### Mass Scanning
- **Parallel Mode**: Test multiple hosts concurrently
- **Serial Mode**: Sequential testing
- **Configurable Workers**: Control parallelism level
- **MX Record Testing**: Scan all mail servers for a domain
- **ASN/CIDR Input**: Scan entire networks via ASN or CIDR ranges

### TLS Fingerprinting
- **JA3**: TLS client fingerprinting with signature database (35+ signatures)
- **JA3S**: TLS server fingerprinting with CDN/Load Balancer detection (56+ signatures)
- **JARM**: Active TLS server fingerprinting with 10 probe handshakes
- **ClientHello/ServerHello Export**: Raw handshake data export (hex, base64, binary formats)

### Certificate Transparency Logs
- **Real-time CT Log Streaming**: Monitor certificates from 50+ Google CT logs
- **Bloom Filter Deduplication**: Efficient duplicate detection with 0.01% false positive rate
- **Sliding Window Algorithm**: 1000 entries per batch with configurable poll intervals
- **Multiple Start Modes**: Real-time (now), beginning (full history), or custom index

### Database Backend (PostgreSQL + SQLite)
- **Dual Backend Support**: Production (PostgreSQL) and development (SQLite)
- **Complete Scan History**: Time-series queries with certificate deduplication
- **SQL Migrations**: 7 migrations with forward compatibility
- **CLI Integration**: --db-config, --store, --history, --cleanup-days
- **Repository Pattern**: Async sqlx with connection pooling
- **Analytics Engine**: Scan comparison, change detection, trend analysis, dashboard generation

### 24/7 Certificate Monitoring
- **Continuous Monitoring**: Configurable scan intervals (hourly, daily, weekly)
- **5 Alert Channels**: Email (SMTP), Slack, Microsoft Teams, PagerDuty, Generic Webhooks
- **8 Change Detection Types**: Certificate renewal, issuer change, key size change, etc.
- **Expiry Warnings**: Multi-threshold alerts (30d, 14d, 7d, 1d before expiration)
- **Alert Deduplication**: Prevent notification spam
- **Graceful Shutdown**: SIGTERM/SIGINT signal handlers
- **Systemd Integration**: Production-ready service unit files

### Policy-as-Code Engine
- **YAML Policy Definitions**: Declarative security policies with full schema validation
- **Policy Inheritance**: Extends keyword for policy reuse
- **Exception Management**: Domain wildcards, rule-specific exceptions, expiration dates
- **CI/CD Integration**: Exit codes for pipeline integration (0=pass, 1=fail)
- **Multiple Action Levels**: FAIL, WARN, INFO
- **3 Output Formats**: Terminal, JSON, CSV

### Compliance Framework Engine
- **7 Compliance Frameworks**:
  - PCI-DSS v4.0.1 (Payment Card Industry)
  - NIST SP 800-52r2 (Federal guidelines)
  - HIPAA (Healthcare encryption)
  - SOC 2 Type II (Cloud/SaaS security)
  - Mozilla Modern (Maximum security)
  - Mozilla Intermediate (Production recommended)
  - GDPR (EU data protection)
- **66 Compliance Requirements**: Protocol, cipher, certificate, signature validation
- **8 Rule Checker Types**: Comprehensive security rule engine
- **4 Output Formats**: Terminal, JSON, CSV, HTML

### REST API Server
- **14 RESTful Endpoints + WebSocket**: Complete API for integration
- **Async Background Jobs**: Concurrent scan execution with job queue
- **API Key Authentication**: 3 permission levels (read, write, admin)
- **Rate Limiting**: 100 req/min per key (configurable)
- **OpenAPI/Swagger**: Auto-generated documentation
- **Real-time Progress**: WebSocket streaming for scan updates
- **Production-Ready**: CORS, compression (gzip/brotli), request logging

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/seifreed/cipherrun.git
cd cipherrun

# Build with cargo
cargo build --release

# The binary will be in target/release/cipherrun
./target/release/cipherrun --help
```

### Using Cargo

```bash
cargo install cipherrun
```

## Quick Start

### Basic Usage

```bash
# Scan a single host
cipherrun example.com

# Scan with specific port
cipherrun example.com:443

# Scan HTTPS URL
cipherrun https://example.com
```

### Protocol Testing

```bash
# Test all protocols
cipherrun -p example.com

# Test cipher suites
cipherrun -E example.com              # Ciphers per protocol
cipherrun -e example.com              # All ciphers
cipherrun --fs example.com            # Forward secrecy
```

### Vulnerability Scanning

```bash
# All vulnerabilities
cipherrun -U example.com

# Specific vulnerabilities
cipherrun -H example.com              # Heartbleed
cipherrun --robot example.com         # ROBOT
cipherrun -O example.com              # POODLE
```

### STARTTLS Testing

```bash
# SMTP
cipherrun -t smtp mail.example.com:587

# IMAP
cipherrun -t imap mail.example.com:143

# Test all MX records for a domain
cipherrun --mx example.com
```

### Output Formats

```bash
# JSON output
cipherrun --json results.json example.com

# JSON (pretty-printed)
cipherrun --json results.json --json-pretty example.com

# CSV output
cipherrun --csv results.csv example.com

# HTML report
cipherrun --html report.html example.com

# All formats at once
cipherrun --json --csv --html example.com
```

### Mass Scanning

```bash
# Create targets file (one target per line)
cat > targets.txt << EOF
google.com:443
github.com:443
cloudflare.com:443
EOF

# Scan serially
cipherrun -f targets.txt

# Scan in parallel (default: 20 concurrent)
cipherrun -f targets.txt --parallel

# Custom parallelism
cipherrun -f targets.txt --parallel --max-parallel 50

# Export results
cipherrun -f targets.txt --parallel --json mass_results.json
```

## Usage Examples

### PCI DSS Compliance Check
```bash
# Check PCI DSS requirements:
# - No SSLv2/SSLv3
# - No TLS 1.0/1.1
# - No weak ciphers
# - Strong certificate
cipherrun payment.example.com:443 --html pci_report.html
```

### Mail Server Security Audit
```bash
# Test SMTP with STARTTLS
cipherrun -t smtp smtp.example.com:587 \
  --json smtp_results.json --json-pretty \
  --html smtp_report.html
```

### API Endpoint Testing
```bash
# Test multiple API endpoints in parallel
cat > api_endpoints.txt << EOF
api.example.com:443
api-staging.example.com:443
api-v2.example.com:443
EOF

cipherrun -f api_endpoints.txt --parallel \
  --json api_security_audit.json --json-pretty
```

### Continuous Security Monitoring
```bash
#!/bin/bash
# Weekly security scan script
DATE=$(date +%Y%m%d)
REPORT_DIR="./reports/$DATE"
mkdir -p "$REPORT_DIR"

# Scan critical hosts
cipherrun -f critical_hosts.txt --parallel \
  --json "$REPORT_DIR/scan_results.json" --json-pretty \
  --html "$REPORT_DIR/scan_report.html"

# Check for vulnerabilities and alert
if grep -q '"vulnerable": true' "$REPORT_DIR/scan_results.json"; then
  echo "ALERT: Vulnerabilities found!" | mail -s "Security Alert" admin@example.com
fi
```

### TLS Fingerprinting Examples

#### JA3 Client Fingerprinting
```bash
# Calculate JA3 fingerprint and detect client
cipherrun example.com:443 --ja3

# Include full ClientHello in JSON output
cipherrun example.com:443 --ja3 --client-hello --json results.json

# Use custom JA3 signature database
cipherrun example.com:443 --ja3 --ja3-db custom_signatures.json
```

#### JA3S Server Fingerprinting
```bash
# Calculate JA3S fingerprint and detect CDN/Load Balancer
cipherrun example.com:443 --ja3s

# Include full ServerHello in JSON output
cipherrun example.com:443 --ja3s --server-hello --json results.json

# Detect CDN infrastructure
cipherrun cdn.example.com:443 --ja3s --json cdn_detection.json
```

#### JARM Active Fingerprinting
```bash
# Perform JARM fingerprinting (10 probes)
cipherrun example.com:443 --jarm

# Export JARM with custom database
cipherrun example.com:443 --jarm --jarm-db signatures.json
```

### Certificate Transparency Log Streaming

```bash
# Start streaming certificates from CT logs
cipherrun --ct-logs

# Start from beginning of all logs
cipherrun --ct-logs --ct-beginning

# Start from custom index
cipherrun --ct-logs --ct-index argon2024=12345

# JSON output with custom poll interval
cipherrun --ct-logs --ct-json --ct-poll-interval 120

# Silent mode (no stats)
cipherrun --ct-logs --ct-silent
```

### Database Backend Examples

#### Initialize Database
```bash
# Generate example config
cipherrun --db-config-example database.toml

# Initialize database (create tables)
cipherrun --db-config database.toml --db-init
```

#### Store and Query Results
```bash
# Store scan results in database
cipherrun example.com:443 --all --db-config database.toml --store

# Query scan history (last 10 scans)
cipherrun --db-config database.toml --history example.com:443

# Query with custom limit
cipherrun --db-config database.toml --history example.com:443 --history-limit 50

# Cleanup old scans (older than 30 days)
cipherrun --db-config database.toml --cleanup-days 30
```

#### Database Analytics
```bash
# Compare two specific scans
cipherrun --db-config database.toml --compare 123:456

# Detect changes in last 7 days
cipherrun --db-config database.toml --changes example.com:443:7

# Analyze trends in last 30 days
cipherrun --db-config database.toml --trends example.com:443:30

# Generate dashboard data
cipherrun --db-config database.toml --dashboard example.com:443:90
```

### Certificate Monitoring Examples

```bash
# Start monitoring daemon
cipherrun --monitor --monitor-config monitor.toml

# Monitor specific domain
cipherrun --monitor --monitor-domain example.com:443

# Monitor multiple domains from file
cipherrun --monitor --monitor-domains domains.txt

# Test alert configuration
cipherrun --test-alert --monitor-config monitor.toml
```

### Policy-as-Code Examples

```bash
# Evaluate policy (report mode)
cipherrun example.com:443 --policy production.yaml

# Enforce policy (CI/CD mode - exit 1 on violations)
cipherrun example.com:443 --policy production.yaml --enforce

# Policy evaluation with JSON output
cipherrun example.com:443 --policy policy.yaml --policy-format json

# Policy evaluation with CSV output
cipherrun example.com:443 --policy policy.yaml --policy-format csv
```

### Compliance Framework Examples

```bash
# List all available compliance frameworks
cipherrun --list-compliance

# Check PCI-DSS v4.0 compliance
cipherrun example.com:443 --compliance pci-dss-v4

# Check NIST SP 800-52r2 compliance
cipherrun example.com:443 --compliance nist-sp800-52r2

# Compliance check with HTML report
cipherrun example.com:443 --compliance pci-dss-v4 --compliance-format html

# Multiple compliance checks
cipherrun example.com:443 --compliance hipaa --compliance soc2
```

### REST API Server Examples

```bash
# Start API server (default: 0.0.0.0:8080)
cipherrun --serve

# Start with Swagger UI documentation
cipherrun --serve --api-swagger

# Custom host and port
cipherrun --serve --api-host 127.0.0.1 --api-port 9000

# Start with configuration file
cipherrun --serve --api-config api.toml

# Generate example API config
cipherrun --api-config-example api.toml

# API server with database backend
cipherrun --serve --db-config database.toml --api-swagger
```

#### API Usage Examples
```bash
# Health check
curl http://localhost:8080/api/v1/health

# Create scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "X-API-Key: demo" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com:443", "all": true}'

# Get scan results
curl http://localhost:8080/api/v1/scan/{id}/results \
  -H "X-API-Key: demo"

# WebSocket progress streaming
wscat -c ws://localhost:8080/api/v1/scan/{id}/stream
```

### Advanced Scanning Features

#### Pre-Handshake Mode (Fast Certificate Retrieval)
```bash
# Fast certificate scanning (2-3x faster)
cipherrun example.com:443 --pre-handshake

# Pre-handshake with multiple targets
cipherrun -f domains.txt --pre-handshake --parallel
```

#### Anycast Detection
```bash
# Scan all resolved IPs (detect Anycast)
cipherrun example.com:443 --scan-all-ips

# Show differences across IPs
cipherrun cdn.example.com:443 --scan-all-ips --json anycast.json
```

#### Custom SNI Options
```bash
# Random SNI generation
cipherrun 1.1.1.1:443 --random-sni

# Reverse PTR SNI lookup
cipherrun 8.8.8.8:443 --reverse-ptr-sni

# Custom SNI hostname
cipherrun 1.1.1.1:443 --sni-name example.com
```

#### ASN and CIDR Scanning
```bash
# Scan entire ASN
cipherrun --asn AS13335

# Scan CIDR range
cipherrun --cidr 1.1.1.0/24

# Parallel scanning with ASN
cipherrun --asn AS13335 --parallel --max-parallel 50
```

#### Probe Status and Timing
```bash
# Show probe status and timing
cipherrun example.com:443 --probe-status

# Show handshake times
cipherrun example.com:443 --show-times
```

#### Hello Data Export
```bash
# Export ClientHello/ServerHello in hex
cipherrun example.com:443 --export-hello hex

# Export in base64
cipherrun example.com:443 --export-hello base64

# Export in binary format
cipherrun example.com:443 --export-hello binary
```

#### DNS-Only and Response-Only Modes
```bash
# Extract only domain names from certificates
cipherrun example.com:443 --dns-only

# Output response data only (no host:port prefix)
cipherrun example.com:443 --response-only
```

#### Custom DNS Resolvers and Rate Limiting
```bash
# Use custom DNS resolvers
cipherrun example.com:443 --resolvers 8.8.8.8,1.1.1.1

# Add delay between connections
cipherrun example.com:443 --delay 500ms

# Rate limiting for mass scanning
cipherrun -f targets.txt --delay 1s --parallel
```

### Certificate Validation Filtering

#### Find All Expired Certificates
```bash
# Scan all domains and show only expired certificates
cipherrun -f production-domains.txt --expired --json expired-certs.json
```

#### Identify Self-Signed Certificates
```bash
# Find self-signed certificates in internal infrastructure
cipherrun -f internal-services.txt --self-signed
```

#### Detect Hostname Mismatches
```bash
# Useful after CDN migrations or multi-domain certificate updates
cipherrun -f cdn-endpoints.txt --mismatched
```

#### Find Any Certificate Issues
```bash
# Combine multiple filters (OR logic - shows certificates matching ANY filter)
cipherrun -f all-domains.txt \
  --expired \
  --self-signed \
  --untrusted \
  --revoked \
  --phone-out \
  --json certificate-issues.json
```

#### Security Audit with Filters
```bash
# Find problematic certificates and generate compliance report
cipherrun -f payment-gateways.txt \
  --expired \
  --untrusted \
  --compliance pci-dss-v4 \
  --compliance-format html
```

See [CERTIFICATE_FILTERS.md](CERTIFICATE_FILTERS.md) for detailed filter documentation.

## Architecture

CipherRun is built with a modular architecture:

```
cipherrun/
├── src/
│   ├── cli/              # Command-line interface (800+ lines)
│   ├── protocols/        # TLS/SSL protocol handling (23 modules)
│   ├── ciphers/          # Cipher suite management
│   ├── vulnerabilities/  # Vulnerability tests (18 checks, 24 modules)
│   ├── certificates/     # Certificate analysis (12 modules)
│   ├── http/             # HTTP header testing
│   ├── client_sim/       # Client simulation (126+ profiles)
│   ├── rating/           # SSL Labs rating (4 modules)
│   ├── starttls/         # STARTTLS protocols (14 types, 18 modules)
│   ├── output/           # Output formatters (13 modules: JSON, CSV, HTML, XML)
│   ├── scanner/          # Main scanning engine
│   ├── fingerprint/      # TLS fingerprinting (9 modules)
│   │   ├── ja3.rs        # JA3 client fingerprinting
│   │   ├── ja3s.rs       # JA3S server fingerprinting
│   │   └── jarm.rs       # JARM active fingerprinting
│   ├── ct_logs/          # Certificate Transparency (7 modules)
│   ├── db/               # Database backend (10 modules)
│   │   ├── models/       # Database models (6 types)
│   │   ├── repositories/ # Repository pattern
│   │   └── analytics/    # Scan analytics (4 modules)
│   ├── monitor/          # Certificate monitoring (8 modules)
│   │   └── alerts/       # Alert channels (5 types)
│   ├── policy/           # Policy-as-Code engine (6 modules)
│   │   └── rules/        # Policy rule types (4 modules)
│   ├── compliance/       # Compliance framework engine (7 modules)
│   ├── api/              # REST API server (29 modules)
│   │   ├── routes/       # API endpoints (7 routes)
│   │   ├── middleware/   # Authentication, CORS, rate limiting
│   │   ├── jobs/         # Background job queue
│   │   └── ws/           # WebSocket streaming
│   ├── input/            # Input handling (ASN/CIDR support)
│   └── utils/            # Utilities (21 modules)
├── data/                 # Reference data
│   ├── cipher-mapping.txt        # 400+ cipher definitions
│   ├── client-simulation.txt     # 126+ client profiles
│   ├── ja3_signatures.json       # 35+ JA3 signatures
│   ├── ja3s_signatures.json      # 56+ JA3S signatures
│   ├── jarm_signatures.json      # JARM signature database
│   ├── compliance/               # 7 compliance frameworks (YAML)
│   │   ├── pci_dss_v4.yaml
│   │   ├── nist_sp800_52r2.yaml
│   │   ├── hipaa.yaml
│   │   ├── soc2.yaml
│   │   ├── mozilla_modern.yaml
│   │   ├── mozilla_intermediate.yaml
│   │   └── gdpr.yaml
│   ├── Mozilla.pem               # Mozilla CA store
│   ├── Apple.pem                 # Apple CA store
│   ├── Linux.pem                 # Linux CA store
│   ├── Microsoft.pem             # Microsoft CA store
│   └── Java.pem                  # Java CA store
├── migrations/           # SQL database migrations (7 files)
├── examples/             # Example configurations
│   ├── monitor.toml      # Certificate monitoring config
│   ├── domains.txt       # Domain list for monitoring
│   ├── policies/         # Example policy files
│   └── docker-compose.monitor.yml
└── tests/                # Integration tests (68 tests)
```

### Key Design Principles

1. **Modularity**: Each feature is encapsulated in its own module
2. **Performance**: Async/await with Tokio for efficient concurrency
3. **Scalability**: Designed to scan thousands of hosts efficiently
4. **Accuracy**: Precise implementation of security checks
5. **Maintainability**: Clear code structure, comprehensive tests

## Performance

CipherRun is optimized for speed:

- **Async I/O**: Built on Tokio runtime
- **Parallel Testing**: Multiple hosts and checks concurrently
- **Minimal Allocations**: Low memory footprint
- **Smart Caching**: DNS, certificate chains, protocol results
- **Connection Reuse**: Efficient connection management

### Benchmarks

On a typical modern system:
- **Single Host Scan**: ~1-3 seconds (full test suite)
- **Pre-Handshake Mode**: ~0.5-1 second (2-3x faster certificate retrieval)
- **Parallel Scanning**: 100+ hosts per minute
- **Mass Scanning**: 1000+ hosts with --parallel --max-parallel 100
- **CT Log Streaming**: 1000 certificates/batch with <0.01% false positives (Bloom filter)
- **Memory Usage**: < 50MB per scan, ~200MB for CT log streaming
- **CPU Usage**: Scales linearly with available cores
- **Database Operations**: <10ms for inserts, <50ms for complex queries
- **API Response Time**: <100ms for scan initiation, real-time WebSocket updates

### Code Statistics

- **Total Lines of Code**: ~50,000+ lines of production Rust
- **Modules**: 150+ source files across 25+ top-level modules
- **Test Coverage**: 484+ tests (unit + integration)
- **Dependencies**: 60+ crates carefully selected for performance and security
- **Binary Size**: ~33MB (release build with LTO and strip)
- **Compilation Time**: ~2-3 minutes (release build)

## Command-Line Options

CipherRun has 100+ command-line options organized into categories:

### Basic Options
```
  [URI]                          Target URI (host:port or URL)
  -f, --file <FILE>              Input file with multiple targets
      --mx <DOMAIN>              Test MX records for a domain
  -t, --starttls <PROTOCOL>      STARTTLS protocol (smtp, imap, pop3, etc.)
  -h, --help                     Print help
  -V, --version                  Print version
```

### Protocol Testing
```
  -p, --protocols                Test all protocols
      --ssl2                     Test only SSLv2
      --ssl3                     Test only SSLv3
      --tls10                    Test only TLS 1.0
      --tls11                    Test only TLS 1.1
      --tls12                    Test only TLS 1.2
      --tls13                    Test only TLS 1.3
      --tlsall                   Test all TLS protocols (skip SSL)
```

### Cipher Testing
```
  -e, --each-cipher              Test all ciphers
  -E, --cipher-per-proto         Test ciphers per protocol
  -s, --std                      Test standard cipher categories
      --fs                       Forward secrecy ciphers only
      --show-ciphers             List all supported ciphers
      --no-ciphersuites          Skip cipher enumeration
```

### Vulnerability Testing
```
  -U, --vulnerable               Test all vulnerabilities
  -H, --heartbleed               Test Heartbleed (CVE-2014-0160)
  -I, --ccs                      Test CCS injection (CVE-2014-0224)
  -T, --ticketbleed              Test Ticketbleed
      --robot                    Test ROBOT
  -R, --renegotiation            Test renegotiation vulnerabilities
  -C, --crime                    Test CRIME (CVE-2012-4929)
  -B, --breach                   Test BREACH (CVE-2013-3587)
  -O, --poodle                   Test POODLE
  -Z, --tls-fallback             Test TLS_FALLBACK_SCSV
  -W, --sweet32                  Test SWEET32 (CVE-2016-2183)
  -A, --beast                    Test BEAST (CVE-2011-3389)
  -L, --lucky13                  Test LUCKY13 (CVE-2013-0169)
      --freak                    Test FREAK (CVE-2015-0204)
  -J, --logjam                   Test LOGJAM (CVE-2015-4000)
  -D, --drown                    Test DROWN (CVE-2016-0800)
      --early-data               Test 0-RTT/Early Data (TLS 1.3)
```

### TLS Fingerprinting
```
      --ja3                      Calculate JA3 client fingerprint [default: true]
      --ja3s                     Calculate JA3S server fingerprint [default: true]
      --jarm                     Calculate JARM server fingerprint [default: true]
      --client-hello             Include ClientHello in JSON output
      --server-hello             Include ServerHello in JSON output
      --ja3-db <FILE>            Custom JA3 signature database
      --ja3s-db <FILE>           Custom JA3S signature database
      --jarm-db <FILE>           Custom JARM signature database
```

### Certificate Transparency
```
      --ct-logs                  Enable CT log streaming mode
      --ct-beginning             Start from beginning of CT logs
      --ct-index <SOURCE=INDEX>  Start from custom index
      --ct-poll-interval <SEC>   Poll interval in seconds [default: 60]
      --ct-batch-size <NUM>      Batch size [default: 1000]
      --ct-json                  Output CT entries as JSON
      --ct-silent                Silent mode (no stats)
```

### Database Backend
```
      --db-config <FILE>         Database configuration file (TOML)
      --store                    Store scan results in database
      --history <HOST:PORT>      Query scan history
      --history-limit <NUM>      Limit for history results [default: 10]
      --cleanup-days <DAYS>      Delete scans older than N days
      --db-init                  Initialize database (create tables)
      --db-config-example <FILE> Generate example database config
```

### Database Analytics
```
      --compare <ID1:ID2>        Compare two scans by ID
      --changes <HOST:PORT:DAYS> Detect changes in last N days
      --trends <HOST:PORT:DAYS>  Analyze trends in last N days
      --dashboard <HOST:PORT:DAYS> Generate dashboard data
```

### Certificate Monitoring
```
      --monitor                  Start monitoring daemon
      --monitor-config <FILE>    Monitoring configuration file (TOML)
      --monitor-domains <FILE>   File with domains to monitor
      --monitor-domain <HOST:PORT> Single domain to monitor
      --test-alert               Test alert channels
```

### Policy-as-Code
```
      --policy <FILE>            Policy file to enforce (YAML)
      --enforce                  Exit with error on policy violations
      --policy-format <FORMAT>   Policy output format [default: terminal]
                                 Options: terminal, json, csv
```

### Compliance Frameworks
```
      --compliance <FRAMEWORK>   Compliance framework to evaluate
                                 Options: pci-dss-v4, nist-sp800-52r2,
                                 hipaa, soc2, mozilla-modern,
                                 mozilla-intermediate, gdpr
      --compliance-format <FORMAT> Compliance output format [default: terminal]
                                   Options: terminal, json, csv, html
      --list-compliance          List available compliance frameworks
```

### REST API Server
```
      --serve                    Start REST API server
      --api-host <HOST>          API server host [default: 0.0.0.0]
      --api-port <PORT>          API server port [default: 8080]
      --api-config <FILE>        API configuration file (TOML)
      --api-max-concurrent <NUM> Max concurrent scans [default: 10]
      --api-swagger              Enable Swagger UI documentation
      --api-config-example <FILE> Generate example API config
```

### Advanced Scanning
```
      --pre-handshake            Pre-handshake mode (fast certificate retrieval)
      --scan-all-ips             Scan all resolved IPs (Anycast detection)
      --random-sni               Use random SNI generation
      --reverse-ptr-sni          Use reverse PTR for SNI
      --probe-status             Show probe status with timing
      --export-hello <FORMAT>    Export Hello data (hex, base64, binary)
```

### Input Options
```
      --asn <ASN>                Scan entire ASN (e.g., AS13335)
      --cidr <CIDR>              Scan CIDR range (e.g., 1.1.1.0/24)
```

### Output Options
```
      --dns-only                 Output only domain names from certificates
      --response-only            Output response data only (no host:port)
      --resolvers <IPS>          Custom DNS resolvers (comma-separated)
      --delay <DURATION>         Delay between connections (e.g., "200ms", "1s")
```

### Certificate Filters
```
  -x, --expired                  Show only expired certificates
  -s, --self-signed              Show only self-signed certificates
  -m, --mismatched               Show only hostname mismatched certificates
  -r, --revoked                  Show only revoked certificates
  -u, --untrusted                Show only untrusted certificates
```

### Output Formats
```
      --json <FILE>              JSON output file
      --json-pretty              Pretty-print JSON
      --csv <FILE>               CSV output file
      --html <FILE>              HTML output file
      --xml <FILE>               XML output file
  -o, --output-all <BASENAME>    Output all formats with basename
```

### Network Options
```
  -4                             Use IPv4 only
  -6                             Use IPv6 only
      --ip <IP>                  Specific IP to test
      --proxy <HOST:PORT>        HTTP proxy
      --test-all-ips             Test all resolved IPs
      --first-ip-only            Scan only first resolved IP
```

### Timing & Retry
```
      --socket-timeout <SEC>     Socket timeout in seconds
      --connect-timeout <SEC>    Connection timeout in seconds
      --sleep <MSEC>             Sleep between requests in milliseconds
      --max-retries <NUM>        Max retries for failures [default: 3]
      --retry-backoff <MSEC>     Initial backoff duration [default: 100]
      --max-backoff <MSEC>       Max backoff duration [default: 5000]
      --no-retry                 Disable retry logic
```

### Miscellaneous
```
  -q, --quiet                    Quiet mode (no banner)
  -v, --verbose                  Verbose output (can be repeated: -vvv)
      --parallel                 Parallel scanning mode
      --max-parallel <N>         Max parallel workers [default: 20]
      --color <MODE>             Color mode (0-3) [default: 2]
      --no-color                 Disable colored output
      --phone-out                Enable CRL/OCSP checks
      --hardfail                 Hard fail on revocation errors
      --show-times               Show handshake times
      --sni-name <NAME>          Custom SNI hostname
  -c, --client-simulation        Test client simulations
  -9, --full                     Run full test suite
```

For complete documentation of all 100+ options, run:
```bash
cipherrun --help
```

## Docker Testing Environment

CipherRun includes a complete Docker testing environment with network analysis tools for debugging and development:

### Quick Start with Docker

```bash
# Build and start environment
make quickstart

# Test a domain
make test-domain DOMAIN=google.com

# Compare ClientHello packets (for debugging TLS issues)
make compare DOMAIN=example.com

# Run batch tests
make batch

# Enter container for manual testing
make shell
```

### Tools Included

- **Network Analysis**: tcpdump, tshark, nmap
- **SSL/TLS Tools**: openssl, sslscan, testssl.sh
- **CipherRun**: Built in release mode
- **Automated Scripts**: Traffic capture, ClientHello comparison, batch testing

### Docker Commands

```bash
make build          # Build Docker image
make run            # Start container
make shell          # Enter container
make stop           # Stop container
make rebuild        # Rebuild from scratch

make compare DOMAIN=<host>   # Compare OpenSSL vs CipherRun ClientHello
make capture DOMAIN=<host>   # Capture traffic during scan
make results                 # Show latest results
make captures                # Show PCAP files
```

See [docs/DOCKER.md](docs/DOCKER.md) for complete Docker documentation.

## Testing

CipherRun includes comprehensive test coverage:

### Unit Tests
```bash
# Run all unit tests
cargo test

# Run with output
cargo test -- --nocapture
```

### Integration Tests
```bash
# Run integration tests (requires network)
cargo test --test integration_badssl -- --ignored
cargo test --test integration_vulnerabilities -- --ignored
cargo test --test integration_starttls -- --ignored
```

### Real Server Testing

CipherRun's integration tests use real servers:
- **badssl.com**: Various TLS misconfigurations
- **Gmail SMTP/IMAP**: STARTTLS testing
- **Major websites**: Google, GitHub, Cloudflare

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/seifreed/cipherrun.git
cd cipherrun
cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- example.com
```

## License and Attribution

This software is licensed under **GPL-3.0**. When using or modifying CipherRun:
- Attribution to the original author (Marc Rivero / @seifreed) is required
- Source code must be published if distributing
- Derivative works must also use the GPL-3.0 license

See the [License](#license) section below for complete details.

---

## Support the Project

If you find CipherRun useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

Your support helps maintain and improve CipherRun.
