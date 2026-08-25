<p align="center">
  <img src="https://img.shields.io/badge/CipherRun-TLS%20Security%20Scanner-blue?style=for-the-badge" alt="CipherRun">
</p>

<h1 align="center">CipherRun</h1>

<p align="center">
  <strong>Fast, modular TLS/SSL security scanner and compliance engine built in Rust</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.88%2B-orange?style=flat-square" alt="Rust Version">
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

Compliance reports are TLS posture checks mapped to selected technical controls. Passing them does not establish certification or full regulatory compliance.

---

## Installation

### From Source

Requires Rust 1.88 or newer.

```bash
git clone https://github.com/seifreed/cipherrun.git
cd cipherrun
cargo build --release
./target/release/cipherrun --help
```

Export the versioned scan-result contract with `cipherrun schema --output
scan-results.schema.json`; the repository copy is maintained at
`docs/scan-results.schema.json`.

The workspace also publishes `cipherrun-core`, a dependency-light crate with
the stable finding status, detection method, vulnerability identifiers, and
structured evidence contracts. It can be used without compiling the CLI, API,
database, or monitoring modules.

It also publishes `cipherrun-protocol`, which exposes the dependency-light
TLS/SSL protocol version and negotiation-result contracts independently of the
scanner implementation.

The `cipherrun-policy` crate provides the versioned policy-definition contracts
without pulling in the evaluator, database, or API server.

The `cipherrun-data` crate provides dependency-light rule-pack metadata
contracts without pulling in the compliance loader or scanner runtime.

The `cipherrun-probes` crate provides dependency-light probe status contracts
without pulling in the scanner networking runtime.

The `cipherrun-cli` crate provides stable process exit-code contracts for
integrations without pulling in the command router.

The `cipherrun-server` crate provides stable permission and job-backend
contracts without pulling in Axum, SQLx, or the scan executor.

The `cipherrun-worker` crate is a standalone worker binary that reuses the
main package's durable queue and scan executor.

Certificate Transparency streaming is enabled by default and can be removed
from a reduced build with `--no-default-features`; `monitoring` depends on
the `ct` feature because CT discovery feeds the monitor sink.

The standalone PQC configuration scanners and roadmap are enabled by the
`pqc` feature; readiness scoring remains part of the core scan-result contract.

### Using Cargo

```bash
cargo install cipherrun
```

### Releases

Pushing a tag matching the package version, such as `v0.4.0`, runs the release workflow. It publishes `cipherrun-core` and then `cipherrun` to crates.io, and attaches platform packages for Linux, Windows, and macOS on x64 and ARM64, together with SHA-256 checksums. The workflow requires the repository Actions secret `CARGO_REGISTRY_TOKEN`.
The same release job generates `cipherrun.rb` and `cipherrun.json` assets from
those checksums for Homebrew and Scoop consumption. It also publishes the versioned production
image to GHCR and signs it keylessly with Sigstore. The local signing helper is
`scripts/sign-container.sh`.

The OpenAPI contract can be exported and used to regenerate the Python client:

```bash
cargo run --bin cipherrun-openapi > /tmp/cipherrun-openapi.json
scripts/generate-python-sdk.sh sdk/python
```

### Docker

The default image is the production build: a distroless, non-root runtime containing only CipherRun and the CA bundle.

```bash
docker build -t cipherrun:0.4.0 .
docker run --rm cipherrun:0.4.0 example.com
```

To run the API, generate credentials first. The production Compose binds the API to localhost, mounts the configuration read-only, drops every capability, and uses a read-only root filesystem.

```bash
cipherrun --api-config-example ./api.toml
export CIPHERRUN_API_CONFIG="$PWD/api.toml"
docker compose -f compose.production.yml up --build
```

The bootstrap command writes only a SHA-256 credential hash to `api.toml` and
places the one-time plaintext token in `api.token`; both files are created with
owner-only permissions and existing files are never overwritten. Move the token
to your secret manager and remove the local token file after enrollment.

Administrators can rotate or revoke credentials without restarting the API:
`GET /api/v1/credentials`, `POST /api/v1/credentials`,
`POST /api/v1/credentials/{key_id}/rotate`, and
`POST /api/v1/credentials/{key_id}/revoke`. Create and rotate responses contain
the new plaintext secret once; list and revoke responses contain metadata only.
Changes are synchronously persisted to the owner-only API TOML file, and the
last active administrator credential cannot be revoked.

### CT Discovery Monitoring

CT streaming can feed the existing monitoring scheduler, scanner, and alert
channels. Configure an explicit suffix allowlist in the monitor TOML:

```toml
[monitor]
ct_discovery_suffixes = ["example.com"]
```

Then run `cipherrun --ct-logs --ct-monitor-config monitor.toml`. CT names are
deduplicated, normalized, and rejected unless they match an allowlisted suffix;
an empty allowlist performs no discovery.

Set `job_storage_dir` in `api.toml` for durable standalone job state. Queued,
running, completed, failed, and cancelled jobs survive restarts; interrupted
running jobs are safely returned to the queue. Omitting it selects the
development-only in-memory backend.
Set `job_backend = "database"` when the API is started with a configured
SQLite or PostgreSQL pool to use the transactional SQL job table instead of
file storage. Database jobs use conditional claims and recover expired running
leases on startup.
For distributed execution, set `local_executor = false` in the API config and
run one or more workers against the same SQL database:

```bash
cipherrun --worker --api-config api.toml --db-config database.toml
```

Workers reuse the scanner, lease heartbeat, retry, dead-letter, webhook, and
CIDR policy code from the API executor; `local_executor = false` is rejected
unless `job_backend = "database"` is selected.
Running jobs renew their database lease while scanning. Transient scan failures
are retried up to three attempts; exhausted jobs remain queryable as failed
dead-letter records instead of being silently discarded.
`job_retention_seconds` controls terminal job TTL (seven days by default);
queued and running work is never removed by retention cleanup.

Browser WebSocket clients obtain a 60-second, one-use URL from
`POST /api/v1/scan/{id}/stream-ticket` using the `X-API-Key` or
`Authorization: Bearer` header. Raw API credentials in query parameters are
rejected.

To enable scan-completion webhooks, point `webhook_signing_secret_file` at an
owner-only file containing at least 32 random bytes. Deliveries include
`X-CipherRun-Event`, `X-CipherRun-Delivery`, `X-CipherRun-Timestamp`, and an
`X-CipherRun-Signature: v1=<hex HMAC-SHA256>` over `<timestamp>.<body>`; transient
failures are retried up to three times.

Authenticated operators can scrape `/api/v1/metrics` in Prometheus text format.
Every API response also carries an `X-Request-ID` value for correlating logs
and client reports. Requests are recorded in a bounded audit ring and emitted
through the structured `audit` tracing target; query strings and bodies are
intentionally excluded.

Credentials assigned to the same `tenant_id` share the configured request quota;
unscoped credentials remain isolated per key.

Set `worker_allowed_cidrs` in the API config to constrain worker DNS results to
administrator-owned network scopes. The client cannot widen this list; every
resolved private address must match an allowlisted CIDR.
Set `trusted_proxy_cidrs` before deploying behind a reverse proxy. `X-Forwarded-For`
is ignored unless the immediate TCP peer belongs to one of these CIDRs.
Historical scans, certificate inventory, and `/api/v1/stats` are scoped to the
authenticated principal and tenant for non-admin credentials. Administrator
credentials retain global visibility; process-wide counters are never exposed to
non-admin callers.

Build with `--features otel` to export tracing spans through the standard OTLP
HTTP exporter. The exporter follows `OTEL_EXPORTER_OTLP_*` environment variables;
without that feature, no telemetry backend is contacted.

Native HTTPS is available by setting `tls_cert_file` and `tls_key_file` to a
certificate chain and private-key PEM file. The two paths must be configured
together; otherwise the API remains HTTP for local development. TLS handshakes
are completed before Axum receives a connection.

Set `tls_client_ca_file` to a PEM CA bundle to require client certificates for
every HTTPS connection (mTLS). Keep the CA file owner-readable and distribute
client certificates separately from API credentials.

`Dockerfile.lab` and `compose.lab.yml` are an explicit packet-capture laboratory with pinned sslscan/testssl.sh sources and digest-pinned SSLyze/TLS-Scanner services. It grants `NET_ADMIN` and `NET_RAW`; use it only on systems and targets you are authorized to test.

```bash
mkdir -p captures results
docker compose -f compose.lab.yml run --rm cipherrun-lab
make lab-validate
```

`make lab-validate` starts isolated weak and modern TLS fixtures, records CipherRun,
sslscan, SSLyze, testssl.sh, TLS-Scanner, and OpenSSL results, and fails when the expected TLS 1.2/1.3
negotiation boundary changes. See the public [validation coverage matrix](docs/validation-coverage.md).

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

# Explicit QUIC/UDP and HTTP/3 probe
cipherrun --quic example.com:443

# Offer Encrypted ClientHello from the target's HTTPS/SVCB record
cipherrun --ech example.com:443

# Cipher enumeration
cipherrun -e example.com

# JSON output
cipherrun --json results.json example.com

# HTML report
cipherrun --html report.html example.com

# CI artifacts
cipherrun --sarif results.sarif --junit results.junit.xml example.com

# CI failure thresholds
cipherrun --fail-on high example.com
cipherrun --policy policy.yaml --fail-on-policy example.com

# Compare versioned scan results (exit 4 on drift)
cipherrun diff baseline.json current.json
cipherrun --baseline baseline.json example.com

# Generate reviewable hardening snippets from a scan result
cipherrun remediate results.json --format nginx
cipherrun remediate results.json --format envoy --output envoy-tls.yaml

# Explicitly authorized internal-network scans (local CLI only)
cipherrun --allow-private intranet.example.internal
cipherrun --allow-cidr 10.20.0.0/16 host.internal

# Scan intensity presets
cipherrun --profile safe example.com
cipherrun --profile standard example.com
cipherrun --profile aggressive example.com
```

### STARTTLS Examples

```bash
# SMTP with STARTTLS
cipherrun -t smtp mail.example.com:587

# IMAP with STARTTLS
cipherrun -t imap mail.example.com:143
```

### JSON Contract

JSON output is versioned independently from the CLI. The canonical schema, compatibility policy, changelog, and fixtures are published in [`schemas/`](schemas/README.md).

Bundled compliance mappings carry an independent rule-pack version, primary
publication reference, review date, and runtime SHA-256 of the exact YAML.

Remote timing probes follow the published [timing methodology](docs/timing-methodology.md),
including sample counts, descriptive statistics, confidence intervals, thresholds,
and the conditions that produce an inconclusive verdict.

`remediate` generates configuration snippets for nginx, Apache, HAProxy, Envoy,
or Caddy. It never changes a running service, and it deliberately leaves
inconclusive or potential findings visible for operator review. Existing output
files are protected unless `--overwrite` is supplied.

---

## QA

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
cargo deny check
cargo +nightly udeps
cargo tarpaulin --engine llvm --all-features --all-targets --no-fail-fast --out Xml
cargo bench
cargo fuzz list
cargo fuzz build parsed_input
cargo outdated
```

Criterion benchmarks live in `benches/`, and `cargo-fuzz` targets plus seed corpora live in `fuzz/`.

---

## Output Formats

```
Terminal, JSON, CSV, HTML, XML, SARIF 2.1.0, JUnit XML
```

Exit codes are stable for automation: `0` success, `1` operational/partial-scan
failure, `2` confirmed finding at the `--fail-on` threshold, and `3` failed
policy or mapped compliance checks. `4` reports drift from `diff` or a baseline.

---

## Architecture

- **Scanner Engine**: Async Tokio-based probes
- **Protocols**: SSLv2 → TLS 1.3
- **Vuln Suite**: 18+ checks
- **Fingerprinting**: JA3/JA3S/JARM
- **Compliance**: 7 frameworks
- **Database**: SQL migrations + analytics

Layer boundaries are enforced by `tests/architecture_guards.rs`.

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

This project is licensed under **GPL-3.0-or-later** - see the [LICENSE](LICENSE) file for details.

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/cipherrun](https://github.com/seifreed/cipherrun)

---

<p align="center">
  <sub>Made with dedication for the security community</sub>
</p>
