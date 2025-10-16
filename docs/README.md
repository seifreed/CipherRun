# CipherRun Documentation

Complete documentation for CipherRun TLS/SSL Security Scanner.

## 📚 Documentation Index

### Getting Started
- [Main README](../README.md) - Installation, quick start, and basic usage
- [CHANGELOG](../CHANGELOG.md) - Version history and recent improvements

### Features & Usage
- [FEATURES.md](FEATURES.md) - Comprehensive feature documentation
  - Protocol support (SSLv2 through TLS 1.3)
  - 400+ cipher suites
  - 18 vulnerability checks
  - Certificate analysis
  - HTTP security headers
  - 126+ client simulations
  - SSL Labs rating
  - 14 STARTTLS protocols
  - Output formats
  - Mass scanning

### Development & Testing
- [DOCKER.md](DOCKER.md) - Docker testing environment
  - Network analysis tools (tcpdump, tshark, nmap)
  - Automated testing scripts
  - Packet capture and analysis
  - ClientHello debugging
  - Batch testing

## 🚀 Quick Links

### Common Tasks

**Basic Scan:**
```bash
cipherrun example.com
```

**Full Security Audit:**
```bash
cipherrun -a example.com --json report.json --html report.html
```

**Test with Docker:**
```bash
make quickstart
make test-domain DOMAIN=example.com
```

**Compare TLS Implementations:**
```bash
make compare DOMAIN=example.com
```

### Command-Line Reference

| Option | Description | Example |
|--------|-------------|---------|
| `-p` | Test protocols | `cipherrun -p example.com` |
| `-e` | Test all ciphers | `cipherrun -e example.com` |
| `-U` | Test vulnerabilities | `cipherrun -U example.com` |
| `-t` | STARTTLS protocol | `cipherrun -t smtp mail.example.com` |
| `-f` | Scan from file | `cipherrun -f targets.txt` |
| `--parallel` | Parallel scanning | `cipherrun -f targets.txt --parallel` |
| `--json` | JSON output | `cipherrun --json out.json example.com` |
| `--html` | HTML report | `cipherrun --html report.html example.com` |

## 📖 Detailed Documentation

### Protocol Support

CipherRun supports all SSL/TLS versions:
- SSLv2, SSLv3 (deprecated, tested for compliance)
- TLS 1.0, 1.1 (deprecated)
- TLS 1.2 (current standard)
- **TLS 1.3 (complete support with 100% compatibility)**

See [FEATURES.md#protocol-support](FEATURES.md#protocol-support) for details.

### Vulnerability Testing

18 comprehensive vulnerability checks including:
- Heartbleed, CCS Injection, Ticketbleed, ROBOT
- POODLE (SSL & TLS), BEAST, CRIME, BREACH
- SWEET32, FREAK, LOGJAM, DROWN
- And more...

See [FEATURES.md#vulnerability-detection](FEATURES.md#vulnerability-detection) for full list.

### Docker Testing

Complete testing environment with:
- tcpdump for packet capture
- tshark for protocol analysis
- Automated comparison scripts
- Batch testing capabilities

See [DOCKER.md](DOCKER.md) for usage guide.

## 🏗️ Architecture

```
cipherrun/
├── src/
│   ├── cli/              # Command-line interface
│   ├── protocols/        # TLS/SSL protocol handling
│   ├── ciphers/          # Cipher suite management
│   ├── vulnerabilities/  # Vulnerability tests
│   ├── certificates/     # Certificate analysis
│   ├── http/             # HTTP header testing
│   ├── client_sim/       # Client simulation
│   ├── rating/           # SSL Labs rating
│   ├── starttls/         # STARTTLS protocols
│   ├── output/           # Output formatters
│   ├── scanner/          # Main scanning engine
│   └── utils/            # Utilities
├── data/                 # Reference data (ciphers, CAs, clients)
├── docs/                 # Documentation
├── tests/                # Integration tests
└── docker/               # Docker testing environment
```

## 🔧 Development

### Building from Source

```bash
git clone https://github.com/seifreed/cipherrun.git
cd cipherrun
cargo build --release
```

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_badssl -- --ignored

# Docker environment
make quickstart
make batch
```

### Debugging TLS Issues

```bash
# Start Docker environment
make quickstart

# Compare ClientHello packets
make compare DOMAIN=problematic-server.com

# Capture traffic
make capture DOMAIN=problematic-server.com

# Analyze with tshark
make shell
tshark -r /captures/latest.pcap -Y tls.handshake -V
```

## 📊 Output Examples

### Terminal Output
Colorized, formatted output with clear sections:
- Protocol support
- Cipher suites
- Certificate details
- Vulnerabilities
- SSL Labs rating

### JSON Output
Structured data for automation:
```json
{
  "target": "example.com:443",
  "protocols": [...],
  "ciphers": [...],
  "certificate": {...},
  "vulnerabilities": [...],
  "rating": {...}
}
```

### HTML Report
Professional report with:
- Styled tables
- Color-coded results
- Sortable columns
- Printable format

## 🎓 Learning Resources

### Understanding TLS/SSL
- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3
- [RFC 5246](https://tools.ietf.org/html/rfc5246) - TLS 1.2
- [SSL Labs Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)

### Security Testing
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)

## 💡 Tips & Best Practices

### For Security Auditors
1. Start with full scan: `cipherrun -a target.com`
2. Export results: Add `--json --csv --html`
3. Review SSL Labs rating
4. Check for critical vulnerabilities
5. Verify certificate chain
6. Test STARTTLS if mail server

### For DevOps
1. Automate with cron jobs
2. Use parallel mode for infrastructure scans
3. Monitor with JSON output + alerting
4. Track changes over time
5. Include in CI/CD pipeline

### For Researchers
1. Use Docker environment for packet analysis
2. Compare implementations with `make compare`
3. Capture traffic with `make capture`
4. Analyze with tshark/wireshark
5. Test against various server types

## 🐛 Troubleshooting

### Connection Issues
```bash
# Use IPv4 only
cipherrun -4 example.com

# Increase timeout
cipherrun --timeout 60 example.com
```

### Certificate Issues
Check:
- Hostname matches certificate
- Certificate not expired
- Chain completeness
- Trusted by major CAs

### TLS 1.3 Issues
Use Docker environment to debug:
```bash
make compare DOMAIN=failing-server.com
```
Compare ClientHello packets with working servers.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/seifreed/cipherrun/issues)
- **Discussions**: [GitHub Discussions](https://github.com/seifreed/cipherrun/discussions)
- **Security**: Report privately (see SECURITY.md)

## 📄 License

GNU General Public License v3.0 - See [LICENSE](../LICENSE)

---

**Built with ❤️ and Rust by Marc Rivero ([@seifreed](https://twitter.com/seifreed))**

Last updated: October 2025
