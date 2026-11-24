<p align="center">
  <img src="https://img.shields.io/badge/CipherRun-TLS%20Security%20Scanner-blue?style=for-the-badge" alt="CipherRun">
</p>

<h1 align="center">CipherRun</h1>

<p align="center">
  <strong>Fast, modular TLS/SSL security scanner and compliance engine built in Rust</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.100%2B-orange?style=flat-square" alt="Rust Version">
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

Requires Rust 1.100 or newer. The Python SDK requires Python 3.12 or newer; CI tests the active minimum (3.12) and the newest active Python release (3.15), updating the matrix when `eol-cli` reports a newer active release. The build matrix pins current GitHub-hosted images: Ubuntu 26.04, Windows Server 2025 with Visual Studio 2026, and macOS 26.

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

The HTTP API stack is enabled by the `api` feature (included by default). A
reduced CLI/library build can disable it with `--no-default-features`; API
server and OpenAPI commands then return an explicit configuration error and
the Axum/Tower/utoipa dependencies are omitted.

The standalone PQC configuration scanners and roadmap are enabled by the
`pqc` feature; readiness scoring remains part of the core scan-result contract.

The reduced feature matrix is checked in CI with `--no-default-features`,
`monitoring`, `ct,pqc`, both database backends, and `--all-features` builds.
Linux CI also runs PostgreSQL repository and coverage tests against PostgreSQL
19.0, the newest active release reported by `eol-cli`.

Database backends are explicit features: `db-sqlite` and `db-postgres` are
enabled by default, and a disabled backend is rejected before opening a pool.

TLS provider selection is explicit as well. The default build enables
`rustls` (the ring provider) and `openssl-legacy` (the reproducible vendored
OpenSSL build). Reduced builds may omit either feature: rustls then uses its
default aws-lc-rs provider, while OpenSSL resolves against the system library.

### Using Cargo

```bash
cargo install cipherrun
```

### Releases

Pushing a tag matching the package version, such as `v0.5.0`, runs the release
workflow. It builds platform packages for Linux, Windows, and macOS on x64 and
ARM64, together with SHA-256 checksums, package-manager manifests, and an SBOM.
The workflow requires the repository Actions secret `CARGO_REGISTRY_TOKEN` for
crates.io publication. The production container and provenance attestations are
separate release outputs and must be verified on the individual GitHub release
before being advertised as published.

The 0.5 migration steps are in [docs/migration-0.5.0.md](docs/migration-0.5.0.md),
the 0.4 migration steps are in [docs/migration-0.4.0.md](docs/migration-0.4.0.md),
the supported platforms and versions are in [docs/support-matrix.md](docs/support-matrix.md),
and automation compatibility rules are in [docs/stability-policy.md](docs/stability-policy.md).
The release job generates `cipherrun.rb` and `cipherrun.json` assets from the
checksums for Homebrew and Scoop consumption. The local container signing helper
is `scripts/sign-container.sh`.

The OpenAPI contract can be exported and used to regenerate the Python client:

```bash
cargo run --bin cipherrun-openapi > /tmp/cipherrun-openapi.json
scripts/generate-python-sdk.sh sdk/python
```

The generator also reapplies the SDK's JSON date/time serialization fix to its output.

### Docker

The default image is the production build: a distroless, non-root runtime containing only CipherRun and the CA bundle.

```bash
docker build -t cipherrun:0.5.0 .
docker run --rm cipherrun:0.5.0 example.com
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
Per-scan progress streams forward only matching scan IDs and close after
completion, failure, cancellation, or a lag notice; reconnect or poll scan
status after a lag notice.

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
without that feature, no telemetry backend is contacted. The application only
installs the global OpenTelemetry provider after its tracing subscriber starts
successfully; constructing the telemetry layer alone has no global side effect.

### Logging and diagnosis

CipherRun uses Rust `tracing`. Logs go to stderr; pass `--logfile FILE` to also
write them to daily-rotated files in a dedicated `.<FILE>.d` directory beside
the requested path. Up to seven daily files are retained. The default level is
`info`; `-v` enables `debug` and `-vv` enables `trace`. `RUST_LOG` takes
precedence and supports standard module directives, for example
`RUST_LOG=warn,cipherrun::api=debug`. Invalid
filters fall back to the selected verbosity. The same filter limits events sent
to OTLP. The standalone worker uses the same `RUST_LOG` filter and defaults to
`info`.
Concurrent initialization calls are serialized; later callers reuse the
already installed global subscriber.
SQLx query statement events are suppressed from CipherRun's built-in text, JSON,
and OTLP destinations because SQL text can contain sensitive literals. Pools
created by CipherRun also disable SQLx statement logging at the connection
level. Keep variable data bound instead of embedding it in SQL text. If an
application installs its own subscriber or supplies its own SQLx pool, that
owner controls statement logging and must keep it disabled or redact it.
Database lifecycle events remain available: successful pool creation emits
`database.pool.connected` with the backend, connection duration, and outcome;
the event omits database paths and connection strings. Successful migration
setup emits `database.migrations.completed` with backend, duration, and
readiness outcome. Scan persistence, repository reads/writes, scan history,
certificate inventory, analytics, and database job-queue operations create
opt-in DEBUG spans with static operation names; they inherit request
correlation and omit SQL, identifiers, and input records. With the `otel`
feature enabled, set a matching `RUST_LOG` directive (for example
`cipherrun=debug`) to export their duration and parent trace context.
DNS cache hit/miss events are `TRACE`-level and omit the hostname, avoiding
per-target debug noise during bulk scans.
HTTP/3 ALPN probes emit one `http3.request.inconclusive` event with aggregate
timeout, connection, and request failure counts; they omit the target and raw
HTTP client errors. Host-bearing `hyper_util::client::legacy` diagnostics stay
disabled even when `RUST_LOG` enables TRACE; CipherRun emits its own sanitized
request outcome instead.
CRL revocation checks emit `certificate.revocation.crl.completed` with `good` or
`revoked` outcome and duration; CRL failures include a stable error code and
duration without logging the distribution-point URL.
OpenSSL certificate-fetch and BEAST probe events retain the active scan-phase
span while their blocking work runs on Tokio's worker pool.
Set `CIPHERRUN_LOG_FORMAT=json` to emit newline-delimited JSON; text is the
default. This setting applies to both the CLI and standalone worker.
Text output escapes control characters in event fields and messages so
untrusted CR, LF, and terminal escape sequences cannot inject log lines or
terminal control sequences; JSON output uses JSON escaping.
Log writes use a bounded background writer and flush on process shutdown. If its
queue fills, low-priority log events may be dropped rather than blocking scans;
the writer guard remains alive for the full command/worker lifetime.
If the drop-monitor thread cannot start, initialization emits a warning and
the accumulated drop count is still reported during shutdown.
The CLI and standalone worker install a panic hook before argument parsing; it
emits a sanitized `process.panic` event (or fixed stderr fallback before logger
initialization) with the source line, never the panic payload. Applications
embedding the library can opt in with `logging::install_safe_panic_hook()`.
The API emits `api_server.background_tasks.shutdown` with duration, task count,
failure count, and completion outcome after joining its background tasks;
individual failed tasks retain their own categorized error events. If the task
owner is dropped before graceful shutdown, `api_server.background_tasks.drop_cleanup`
records whether a shutdown signal was sent and whether the executor cleanup could
be scheduled in the active Tokio runtime. Background tasks spawned through the
shared Tokio helper retain both the active tracing subscriber and span across
worker threads. The executor, job-retention, and rate-limit cleanup tasks inherit
the server's current tracing context.
`scan_job.task.join_failed` classifies unexpected task panics and cancellations
with stable error codes and an outcome; its structured event omits the panic
payload. Parallel mass-scan tasks inherit the command span; join failures use
the same safe categorization and return a fixed error message without exposing
panic payloads or target names in the diagnostic event.
Monitoring logs inventory loads, manual additions, allowlisted CT discovery
counts, scan outcomes, and per-channel alert delivery outcomes without logging
the monitored hostnames. Its `monitor.started` event follows inventory and
configuration readiness. Signal-handler setup/runtime failures emit categorized
events, and a setup failure resets the daemon's running state.
Target-validation and certificate-fetch failure events include elapsed scan
duration and categorized errors without logging the monitored target.
When idle, a shutdown request wakes the scheduler immediately instead of waiting
for the next poll tick; an active scan cycle finishes before `monitor.stopped`.
Anycast diagnosis records DNS resolution timing/failure and per-address scan
outcomes by index, without logging hostnames or IP addresses.
JARM emits one `DEBUG` completion summary with probe count, inconclusive count,
duration and outcome; it omits the target and raw handshake data.
The explicit `--probe-status` option emits one connectivity event with duration,
outcome and error category, without the target address.
Optional pre-handshake capture failures emit a `DEBUG`
`scan.preflight.capture.failed` event with operation, duration, error category,
and outcome, without the target name or address.
MX lookup failures emit a terminal `dns.mx.lookup.failed` event with duration
and a stable error code; resolver output and domain names stay out of that event.
CT stream shutdown events include elapsed time and a terminal outcome, both for
the overall stream and each source. Signal, output, and stats tasks inherit the
current command span; each source task has its own `ct_log.source` span. Dropping
the stream future aborts its owned tasks, and source-health validation happens
before any background task starts.
Completed CLI commands and standalone worker runs emit one terminal event with
operation, duration, outcome and exit/error type; they do not log scan targets
or raw error text.
Successful scan completion webhook events include the attempt count, duration
and outcome; terminal failures include duration and a stable error code without
exposing webhook URLs or response details.
The `--local` OpenSSL inventory emits one terminal outcome for the combined
version and cipher-list operation, while its result stays on stdout.
If an OpenSSL subprocess remains active after a timeout but the operating
system refuses the termination request, a separate sanitized warning records
that process-control failure.
The API TLS listener reports accept failures with a retry delay and outcome; its
backoff grows from 100 ms to a 5 s cap to limit CPU and warning volume during
persistent listener errors.

API middleware creates a `http.request` span with the generated `request_id`,
HTTP method, and matched route template around downstream request handling.
The span is carried through scan WebSocket upgrades and their send/receive tasks,
and queued scan jobs retain their `scan.job` span through the spawned scan task,
so asynchronous diagnostics retain their operation context. The response's
`X-Request-ID` can be used to find that request's structured audit event and
related spans. Unmatched paths use a fixed marker; client IPs, query strings,
request bodies and authorization headers are not written to logs. Do not add credentials,
webhook URLs, certificate contents, or alert message bodies to tracing fields.
Production blocking probes and email alert sends use the same current-span
propagation helper, so their diagnostics remain attached to the active scan or
monitor operation. The standalone worker's executor and monitor's per-domain
scans and signal handlers also retain the invoking command span.

With the `otel` feature enabled, tracing spans are exported through OTLP over
HTTP. Export failures produce sanitized SDK error events through `tracing`; the
collector's response body is not included. Transient HTTP failures are retried
up to three times with exponential backoff and jitter; after the initial attempt
and retries are exhausted, the batch is reported as failed and may be lost.
`OTEL_EXPORTER_OTLP_TIMEOUT` (or `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT`) limits
each HTTP request attempt. This uses the Rust OTLP SDK's opt-in
`experimental-http-retry` feature. Without `otel`, logs and spans remain local
and no telemetry service is required.

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

# Telnet with STARTTLS
cipherrun -t telnet legacy.example.com:23
```

### JSON Contract

JSON output is versioned independently from the CLI. The canonical schema, compatibility policy, changelog, and fixtures are published in [`schemas/`](schemas/README.md).

Bundled compliance mappings carry an independent rule-pack version, primary
publication reference, review date, and runtime SHA-256 of the exact YAML.
Trust-store and fingerprint refreshes are traceable through the generated
[data provenance manifest](docs/data-provenance.md), which records their
source, revision, counts, and SHA-256 values.

Remote timing probes follow the published [timing methodology](docs/timing-methodology.md),
including sample counts, descriptive statistics, confidence intervals, thresholds,
and the conditions that produce an inconclusive verdict.

Client simulations expose a versioned compatibility contract with explicit
rustls and metadata-only limitations; see
[client compatibility profiles](docs/client-compatibility-profiles.md).
Delegated-credential checks parse OpenSSL's decrypted TLS 1.3 `Certificate`
handshake and verify RFC 9345 extension 34 when present; TLS 1.2 uses the
X.509 prerequisite fallback and certificate-only backends conservatively report
`not_observed`. Full positive/negative
interoperability validation still requires dedicated RFC 9345 server fixtures.
See [delegated credentials](docs/delegated-credentials.md).

`remediate` generates configuration snippets for nginx, Apache, HAProxy, Envoy,
or Caddy. It never changes a running service, and it deliberately leaves
inconclusive or potential findings visible for operator review. Existing output
files are protected unless `--overwrite` is supplied.

External audit status and the exact pre-audit evidence commands are tracked in
[`docs/security-audit.md`](docs/security-audit.md); the checklist is not a
substitute for an independent audit.

---

## QA

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
# SQLx 0.8 retains rsa through its inactive optional MySQL driver in Cargo.lock.
# The quality gate checks all enabled features before applying this exception.
cargo tree --all-features --target all --locked -e features -i rsa -q
cargo audit --ignore RUSTSEC-2023-0071
cargo deny check
cargo +nightly udeps
cargo llvm-cov --workspace --all-features --all-targets --locked --fail-under-lines 87.9 --summary-only
cargo bench
cargo fuzz list
cargo fuzz build parsed_input
cargo outdated
```

CI measures line coverage across every Rust workspace crate, feature, and target. The latest complete local run measured 88.21% (99,985/113,346 lines) with Rust 1.100.0 and `cargo-llvm-cov` 0.9.1; it passed the 88.1% floor. `src/fingerprint/server_hello.rs`, `src/output/probe_status.rs`, `src/protocols/renegotiation/client_hello.rs`, `src/starttls/sieve.rs`, and `src/vulnerabilities/tester/cipher_checks.rs` now have 100% line coverage; the tests cover malformed record and handshake framing, truncated fields and extensions, serialized ClientHello record/handshake/extension lengths, maximum u16 CCS record length rejection, Sieve negotiator constructors, serialization bounds, extension ordering, every alert description, CR/LF/ESC injection including a trailing LF in text logs, empty-queue executor startup and shutdown events, both short-input and UTF-8-boundary paths in terminal error formatting, and BEAST SSL 3.0 CBC and non-CBC classification. The run also covered HTTPS CRL distribution-point extraction, rejection of unsupported LDAP URLs, DROWN SSLv2 buffer/error classification, OpenSSL STARTTLS protocol mappings, fragmentation, truncated records, invalid feature-detection responses, Winshock TLS EOF/timeout handling, MySQL banner versions and declared-length validation, SQLite scan-repository error mapping, PostgreSQL scan-repository and certificate-comparison success/error paths, Heartbleed response framing, worker startup configuration/database failures, GREASE ClientHello generation, SNI behavior, alert outcomes and oversized-record rejection, renegotiation ServerHello extension parsing, missing-scan comparator failures, safe OCSP AIA URL extraction, trust-chain issuer and CA-subject mismatch rejection, CLI help and pre-logger parse-error paths, default JA3/JA3S/JARM database loading, continuation of the fingerprint phase when JA3/JA3S/JARM connections fail, certificate signature fallbacks for DER bytes, serialized metadata, and empty chains, non-UTF-8 W3C trace header rejection, and global plus owner-scoped API statistics recording. Logger initialization is also exercised in isolated child processes for JSON, text, and file-destination fallback output. Linux CI verifies rejection of persisted job files whose filename is not valid UTF-8 and runs the PostgreSQL paths against 19.0, the newest active release reported by `eol-cli`. The two 30-second rolling-file load tests run under `cargo llvm-cov`; regular `cargo test` continues to skip them. The floor must rise as uncovered paths receive tests; the target is 100%.

Cipher strength trend analysis reports a database error for persisted scan history rows without an ID instead of silently omitting them.

CI artifact upload and release download use the Node 24-compatible, SHA-pinned `upload-artifact` 7.0.2 and `download-artifact` 8.0.2 actions.

The differential TLS lab pins each OpenSSL probe to the fixture's expected protocol; TLS 1.0/1.1 probes lower the client cipher security level because current OpenSSL defaults no longer negotiate those legacy protocols.
Scheduled CI uses the latest Kani release (0.68.0) and fuzzes `parsed_input` and `framework_loader` for 120 seconds each. Kani 0.68.0 currently hits an upstream codegen ICE in this crate. Kani 0.67.0 is not a workaround: its bundled Rust 1.93 compiler is below the project's Rust 1.100 MSRV. The formal-verification job remains an open upstream compatibility issue; retry the latest Kani release after the ICE is fixed.

`cargo deny` temporarily ignores the maintenance-only `RUSTSEC-2026-0543`
advisory for `chrono`, which has no safe upgrade and remains required by SQLx
and the date/time API models. Reassess the exception by 2027-06-30; it does not
ignore vulnerability advisories, and `cargo audit` still reports the maintenance
warning.

Criterion benchmarks live in `benches/`, and `cargo-fuzz` targets plus seed corpora live in `fuzz/`.

Run the manual API and logging soak with:

```bash
cargo test --test api_rate_limit_tests api_logging_load_soak_accounts_for_requests_and_events -- --ignored --nocapture
```

It exercises the local authenticated `/health` route, request metrics and JSON
logging for 30 seconds with eight concurrent producers, and fails if any log
events are dropped. This synthetic local-file test checks capture under its
fixed workload; its throughput and latency do not establish a production SLO.

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
