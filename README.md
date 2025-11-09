# CipherRun

**A Fast, Modular, and Scalable TLS/SSL Security Scanner Written in Rust**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Author](https://img.shields.io/badge/Author-@seifreed-green.svg)](https://twitter.com/seifreed)
[![Attribution Required](https://img.shields.io/badge/Attribution-Required-red.svg)](NOTICE)

<a href="https://buymeacoffee.com/seifreed" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

CipherRun is a comprehensive TLS/SSL security scanner written in Rust, designed for superior performance, scalability, and modern security testing capabilities.

**Author**: Marc Rivero ([@seifreed](https://twitter.com/seifreed))

> **📢 IMPORTANT**: This software is licensed under GPL-3.0. If you use or modify CipherRun:
> - **You MUST credit the author** (Marc Rivero / @seifreed)
> - **You MUST publish your source code** if distributing
> - **Modifications MUST use GPL-3.0** license

## ✨ Features

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

### 🛡Vulnerability Detection (18 Checks)
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
- **Log Files**: Complete session logs

### Mass Scanning
- **Parallel Mode**: Test multiple hosts concurrently
- **Serial Mode**: Sequential testing
- **Configurable Workers**: Control parallelism level
- **MX Record Testing**: Scan all mail servers for a domain

## 📦 Installation

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

## 🚀 Quick Start

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

## 🏗Architecture

CipherRun is built with a modular architecture:

```
cipherrun/
├── src/
│   ├── cli/              # Command-line interface
│   ├── protocols/        # TLS/SSL protocol handling
│   ├── ciphers/          # Cipher suite management
│   ├── vulnerabilities/  # Vulnerability tests (18 checks)
│   ├── certificates/     # Certificate analysis
│   ├── http/             # HTTP header testing
│   ├── client_sim/       # Client simulation
│   ├── rating/           # SSL Labs rating
│   ├── starttls/         # STARTTLS protocols (14 types)
│   ├── output/           # Output formatters
│   ├── scanner/          # Main scanning engine
│   ├── data/             # Data file parsing
│   └── utils/            # Utilities
├── data/                 # Reference data
│   ├── cipher-mapping.txt        # 400+ cipher definitions
│   ├── client-simulation.txt     # 126+ client profiles
│   ├── Mozilla.pem               # Mozilla CA store
│   ├── Apple.pem                 # Apple CA store
│   ├── Linux.pem                 # Linux CA store
│   ├── Microsoft.pem             # Microsoft CA store
│   └── Java.pem                  # Java CA store
└── tests/                # Integration tests
```

### Key Design Principles

1. **Modularity**: Each feature is encapsulated in its own module
2. **Performance**: Async/await with Tokio for efficient concurrency
3. **Scalability**: Designed to scan thousands of hosts efficiently
4. **Accuracy**: Precise implementation of security checks
5. **Maintainability**: Clear code structure, comprehensive tests

## ⚡ Performance

CipherRun is optimized for speed:

- **Async I/O**: Built on Tokio runtime
- **Parallel Testing**: Multiple hosts and checks concurrently
- **Minimal Allocations**: Low memory footprint
- **Smart Caching**: DNS, certificate chains, protocol results
- **Connection Reuse**: Efficient connection management

### Benchmarks

On a typical modern system:
- **Single Host Scan**: ~1-3 seconds (full test suite)
- **Parallel Scanning**: 100+ hosts per minute
- **Memory Usage**: < 50MB per scan
- **CPU Usage**: Scales with available cores

## Command-Line Options

```
Usage: cipherrun [OPTIONS] [URI]

Arguments:
  [URI]  Target URI (host:port or URL)

Options:
  -f, --file <FILE>              Input file with multiple targets
      --mx <DOMAIN>              Test MX records for a domain
  -t, --starttls <PROTOCOL>      STARTTLS protocol (smtp, imap, pop3, etc.)
  -p, --protocols                Test all protocols
  -e, --each-cipher              Test all ciphers
  -E, --cipher-per-proto         Test ciphers per protocol
  -s, --std                      Test standard cipher categories
      --fs, --fs-only            Forward secrecy ciphers only
  -U, --vulnerable               Test all vulnerabilities
  -H, --heartbleed               Test Heartbleed
  -I, --ccs, --ccs-injection     Test CCS injection
      --ticketbleed              Test Ticketbleed
      --robot                    Test ROBOT
  -O, --poodle                   Test POODLE (SSL)
  -B, --beast                    Test BEAST
  -C, --crime                    Test CRIME
      --breach                   Test BREACH
      --sweet32                  Test SWEET32
  -F, --freak                    Test FREAK
  -J, --logjam                   Test LOGJAM
  -D, --drown                    Test DROWN
  -4                             Use IPv4 only
  -6                             Use IPv6 only
  -9, --full                     Include tests that take a while
      --json <FILE>              JSON output file
      --json-pretty              Pretty-print JSON
      --csv <FILE>               CSV output file
      --html <FILE>              HTML output file
  -q, --quiet                    Quiet mode (no banner)
  -v, --verbose                  Verbose output
      --parallel                 Parallel scanning mode
      --max-parallel <N>         Max parallel workers [default: 20]
  -h, --help                     Print help
  -V, --version                  Print version
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

## 🧪 Testing

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

## License

CipherRun is licensed under the **GNU General Public License v3.0**.

### What This Means

**You CAN:**
- ✅ Use CipherRun for personal or commercial purposes
- ✅ Modify the source code
- ✅ Distribute copies of the software
- ✅ Distribute your modifications

**Summary:**
- **Free to use** - No cost, for any purpose
- **Attribution required** - You must credit the author
- **Open source required** - Modifications must be published
- **Copyleft** - Derivative works must use GPL-3.0

### Why GPL-3.0?

This license ensures that:
1. The software remains free and open source forever
2. Contributors get proper credit
3. Improvements benefit the entire community
4. No one can make a closed-source derivative

See [LICENSE](LICENSE) for full legal text.

---

## ☕ Support the Project

If you find CipherRun useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

Your support helps maintain and improve CipherRun. Thank you! 🙏
