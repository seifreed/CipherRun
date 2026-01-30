<p align="center">
  <img src="https://img.shields.io/badge/CipherRun-TLS%20Security%20Scanner-blue?style=for-the-badge" alt="CipherRun">
</p>

<h1 align="center">CipherRun</h1>

<p align="center">
  <strong>Fast, modular TLS/SSL security scanner and compliance engine built in Rust</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.70%2B-orange?style=flat-square" alt="Rust Version">
  <a href="https://crates.io/crates/cipherrun"><img src="https://img.shields.io/crates/v/cipherrun?style=flat-square&logo=rust&logoColor=white" alt="Crates.io Version"></a>
  <a href="https://github.com/seifreed/cipherrun/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/cipherrun/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://github.com/seifreed/cipherrun"><img src="https://img.shields.io/github/stars/seifreed/cipherrun?style=flat-square" alt="GitHub Stars"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/cipherrun/issues"><img src="https://img.shields.io/github/issues/seifreed/cipherrun?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**CipherRun** is a comprehensive TLS/SSL security scanner written in Rust. It combines protocol and cipher analysis, vulnerability testing, compliance checks, and certificate transparency monitoring in a single high-performance CLI and API-ready engine.

### Key Features

| Feature | Description |
|---------|-------------|
| **Protocol Coverage** | SSLv2 to TLS 1.3 with full handshake analysis |
| **Vulnerability Tests** | 18+ major TLS CVEs (Heartbleed, ROBOT, POODLE, LOGJAM, etc.) |
| **Compliance Engine** | PCI-DSS, NIST, HIPAA, SOC 2, Mozilla, GDPR |
| **Fingerprinting** | JA3, JA3S, JARM with signature databases |
| **Certificate Analysis** | Chain validation, revocation, EV detection |
| **Monitoring** | 24/7 certificate monitoring with alerts |
| **CT Logs** | Real-time CT log streaming + Bloom deduplication |
| **Database Support** | PostgreSQL/SQLite analytics and history |

---

## Installation

### From Source

```bash
git clone https://github.com/seifreed/cipherrun.git
cd cipherrun
cargo build --release
./target/release/cipherrun --help
```

### Using Cargo

```bash
cargo install cipherrun
```

---

## Quick Start

```bash
# Scan a host
cipherrun example.com

# Scan a URL
cipherrun https://example.com

# Run full vulnerability scan
cipherrun -U example.com
```

---

## Usage

### Common Commands

```bash
# Protocol testing
cipherrun -p example.com

# Cipher enumeration
cipherrun -e example.com

# JSON output
cipherrun --json results.json example.com

# HTML report
cipherrun --html report.html example.com
```

### STARTTLS Examples

```bash
# SMTP with STARTTLS
cipherrun -t smtp mail.example.com:587

# IMAP with STARTTLS
cipherrun -t imap mail.example.com:143
```

---

## Output Formats

```
Terminal, JSON, CSV, HTML, XML
```

---

## Architecture (High Level)

- **Scanner Engine**: Async Tokio-based probes
- **Protocols**: SSLv2 → TLS 1.3
- **Vuln Suite**: 18+ checks
- **Fingerprinting**: JA3/JA3S/JARM
- **Compliance**: 7 frameworks
- **Database**: SQL migrations + analytics

---

## Contributing

Contributions are welcome:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If you find CipherRun useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under **GPL-3.0** - see the [LICENSE](LICENSE) file for details.

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/cipherrun](https://github.com/seifreed/cipherrun)

---

<p align="center">
  <sub>Made with dedication for the security community</sub>
</p>
