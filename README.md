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

Requires Rust 1.100 or newer. The Python SDK requires Python 3.12 or newer; CI tests the active minimum (3.12) and newest active release (3.15), using the latest patch release for each. Rust uses the `stable` channel. CI follows GitHub's `*-latest` runner aliases (currently Ubuntu 26.04, Windows Server 2025 with Visual Studio 2026, and macOS 26); release builds keep explicit OS baselines where compatibility requires them.

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
Linux CI also runs PostgreSQL repository and coverage tests against the latest
PostgreSQL image (`postgres:latest`; currently 19.0), matching the newest active
release reported by `eol-cli` and following future major and patch updates.
The same CI workflow runs weekly so moving Rust, Python, PostgreSQL, and runner
aliases are revalidated even when the repository has no new commits.

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
The x86_64 Linux artifact is built on Ubuntu 24.04 to retain its glibc baseline;
the ARM64 Linux artifact uses the current Ubuntu 26.04 ARM runner.
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
status after a lag notice. After a terminal or lag frame, the server waits up to
one second for the peer to finish the WebSocket close handshake, then logs a
structured timeout and closes the connection.

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
cargo llvm-cov --workspace --all-features --all-targets --locked --fail-under-lines 90.66 --summary-only
cargo bench
cargo fuzz list
cargo fuzz build parsed_input
cargo outdated
```

CI measures line coverage across every Rust workspace crate, feature, and target using `cargo-llvm-cov` 0.9.2. The latest complete local all-targets run measured 90.819995% (109,904/121,013 lines) with Rust 1.100.0 and `cargo-llvm-cov` 0.9.2; Linux CI enforces a 90.66% floor and publishes its measured workspace percentage in the GitHub Actions step summary. The CI and local quality-gates coverage commands use the same 90.66% floor. CVSS tests also capture the negative-score warning as JSON and assert its severity, stable event name, score, and fallback fields. TLS rating tests cover QUIC neutrality, key-exchange and weak-cipher penalty thresholds, certificate grade overrides, and confirmed vulnerability penalties across all severities. `src/rating/scoring.rs` now has 100% line coverage, including the no-weak-cipher penalty path. Stream-ticket tests cover malformed and oversized tokens, invalid signatures and claims, expired or scan-mismatched tickets, single-use enforcement, issued-claim mismatch, expired-entry cleanup, capacity limits, and secure-random/serialization failures. A signing failure during ticket issuance also verifies no ticket is persisted. API error response tests also verify the not-found builder and explicitly flush the captured structured error writer. Scan executor logging tests call the captured writer flush implementation directly. Executor finalization tests cover successful result persistence and completion metrics, a redacted result-store failure outcome, a cancellation racing with final status persistence without publishing a false completion, and a final-status persistence failure that suppresses terminal progress and webhooks. Scan WebSocket tests also verify periodic ping frames on per-scan streams and processing of client Ping, Pong, text, binary, and Close frames. CT streamer tests also verify an HTTP 503 batch failure is retried, logged with a safe structured event, and does not expose the endpoint URL. Analytics command test fixtures serialize SQLite paths as TOML values so Windows backslashes remain valid. PostgreSQL protocol-comparison integration coverage now checks added, removed, unchanged, and preferred-protocol changes against an isolated schema. The same fixture drops its isolated table to verify query errors retain comparison context. PostgreSQL change-tracker tests also execute every change-source query against isolated tables. Reverse PTR tests use an isolated loopback DNS server to verify IPv4 and IPv6 forward confirmation, invalid PTR hostnames, empty PTR answers, and mismatched forward records. Scan executor coverage now verifies retry scheduling failures produce a failed outcome and a redacted structured event. Job storage construction tests exercise successful owned and borrowed `PathBuf` inputs as well as a filesystem creation failure. Adaptive-controller tests cover retry-limit getters and poisoned-mutex recovery with a structured warning event. `src/constants.rs` now has 100% line coverage, including every handshake-name mapping and both SSL 2.0 version encodings. Curve database tests cover its empty fallback, ignored blank/comment lines, and malformed embedded-data error wrapping; `src/data/curves.rs` now has 100% line coverage. Heartbleed classification tests cover short valid responses below the suspicious-size threshold, small valid leak warnings, and malformed responses. `src/vulnerabilities/heartbleed/heartbeat_probe.rs` now has 100% line coverage. `src/api/jobs/storage.rs` now has 100% line coverage; its tests verify successful persistence and reload of completed jobs, error paths, and that a failed atomic persist leaves an existing destination directory intact. `src/utils/dns_cache.rs` also has 100% line coverage, including both cleanup-threshold outcomes. `src/protocols/intolerance/orchestration.rs` now has 100% line coverage: detection, clean and inconclusive outcomes are verified for all checks, with SNI alert and common DH prime classification tested independently. A loopback TLS 1.2 DHE test now covers successful weak-prime extraction and verifies the client reads the peer ephemeral key. Intolerance network tests cover partial replies, EOF, timeout handling, and the bounded response buffer. A direct stats-route test also verifies that the captured log writer flushes successfully. Target parsing tests cover malformed URLs, bracketed IPv6 addresses with and without ports, invalid IPv6 ports, and warnings for malformed IPv6 input. The security input validator also has a direct rejection test for malformed unbracketed IPv6. STARTTLS port mapping tests cover POP3, NNTP, XMPP, XMPP-server, and PostgreSQL defaults. Webhook SSRF tests verify public DNS results are accepted and ordered with IPv4 first. NPN probe tests verify a valid ServerHello without the NPN extension is reported as not supported. Compliance framework-source tests cover valid on-disk YAML and missing, oversized, invalid UTF-8, malformed YAML, invalid metadata, and unknown-ID outcomes. Analytics CLI tests exercise compare, changes, trends, and dashboard behavior against an empty SQLite history in terminal and JSON modes; Windows paths in its TOML fixture are serialized safely. CVSS tests verify all metric enums, severity boundaries, score labels, and predefined TLS vulnerability vectors, including the low-severity, low-privilege, and changed-scope string mappings. The API request middleware test captures the structured completion event and verifies request-ID correlation, route-template normalization, status, duration, and omission of dynamic path values. Scan result route tests also verify failed and cancelled jobs return distinct safe diagnostics without exposing private failure details. Idempotency-Key validation tests cover missing, valid, duplicate, empty, oversized, and invalid-byte header values. Scan creation logging tests capture the structured queued event and verify outcome, duration, and hostname minimization. Scan route tests also cover successful results retrieval and the successful cancellation of a queued job. They also verify missing completed results map to an internal error without exposing the scan target; the queued-event test exercises a valid idempotency key and confirms it is not logged. The WebSocket route test confirms a client without either an API key or one-use ticket receives HTTP 401. Stream-ticket route coverage now verifies owner-scoped ticket issuance, single-use consumption, and replay rejection. Ownership tests also confirm a different principal receives 404 for ticket creation and WebSocket access. Panic-hook event tests verify structured diagnostics retain a static error code and source line without exposing panic payloads. Subscriber lifecycle event tests also verify stable structured fields for initialization and reuse. Scan cancellation tests cover a lost queue race, safe cancellation logging, and the administrator authorization path. GitHub Actions exposed a small Linux-versus-local coverage difference at the 90.67% gate, so CI now uses a 90.66% floor. GREASE outcome tests verify connection errors and missing test evidence remain inconclusive. Additional CA loading falls back to DER when OpenSSL returns an empty PEM bundle; local tests cover PEM, DER, ignored invalid files, and empty directories. SQLite change-tracker tests cover added, removed, increased, decreased, and same-score rating changes plus overall rating changes. They also verify a missing ratings table returns a contextual query error. `src/scanner/multi_ip/progress.rs` now has 100% line coverage, including default construction and singular/plural consistency summaries. `src/fingerprint/server_hello.rs`, `src/output/probe_status.rs`, `src/protocols/renegotiation/client_hello.rs`, `src/starttls/sieve.rs`, `src/scanner/orchestration/multi_ip.rs`, `src/vulnerabilities/ticketbleed/read_io.rs`, and `src/scanner/aggregation/mod.rs` now have 100% line coverage; Ticketbleed record reads cover full buffers, timeouts, EOF, partial records, and oversized-record rejection; session-ticket extraction also scans across TLS records and handshake messages and handles empty and non-handshake responses; ServerHello tests verify detection requires bytes beyond the client session marker; DROWN SSLv2 reader tests cover oversized responses, immediate EOF, empty or partial read timeouts, and injected read errors; received session tickets larger than the TLS u16 extension limit are rejected during ClientHello construction; protocol model tests also exercise writer flush behavior in both the root crate and standalone protocol crate; the tests cover malformed record and handshake framing, truncated ClientHello capture fields, extension blocks and headers, and invalid SNI/vector lengths, complete/truncated/oversized renegotiation records, truncated fields and extensions, serialized ClientHello record/handshake/extension lengths, maximum u16 CCS record length rejection, Sieve negotiator constructors, serialization bounds, extension ordering, every alert description, CR/LF/ESC injection including a trailing LF in text logs, empty-queue executor startup and shutdown events including a closed shutdown signal channel, immediate shutdown before startup with structured started/draining/shutdown event assertions, and requeueing a job when shutdown interrupts slot acquisition, containing and logging a panicked scan task while the executor continues dispatching, both short-input and UTF-8-boundary paths in terminal error formatting, and BEAST SSL 3.0 CBC and non-CBC classification. A SQLite certificate-comparison test also verifies typed errors for invalid stored values in 14 certificate columns. SQLite child-row persistence tests also verify that failed vulnerability and rating inserts preserve their operation context. Empty child collections are verified as no-op persistence operations. Certificate parser tests also exercise mTLS configuration retention and STARTTLS host, protocol, and server-mode options. The run also covered HTTPS CRL distribution-point extraction, missing distribution-point handling, and rejection of unsupported LDAP URLs, DROWN SSLv2 buffer/error classification, including loopback reads of TLS replies, incomplete headers, and complete records, OpenSSL STARTTLS protocol mappings, IRC CAP LS continuation-limit rejection, fragmentation, truncated records, invalid feature-detection responses, Winshock TLS EOF/timeout handling, including direct EOF, partial-record, empty-buffer, and read-error propagation tests for the async record reader, MySQL banner versions and declared-length validation, SQLite scan-repository error mapping, PostgreSQL scan-repository and certificate-comparison success/error paths, PostgreSQL history pagination, ordering, principal/tenant filters including null tenants, valid and malformed history-row fields, PostgreSQL connection-pool health, insert/upsert and optional-ID queries, owner-filtered top domains, and every typed bind value, PostgreSQL certificate inventory expiry/hostname/owner filters and ordering, tenantless access, normalized fingerprint lookups, and owner denial, CRIME ServerHello compression classification and malformed NPN extension handling, SQLite migration ordering, idempotence, rollback, and malformed migration diagnostics, Heartbleed response framing, worker startup configuration/database and logging-initialization failures, plus structured worker completion and redacted failure events, GREASE ClientHello generation, SNI behavior, alert outcomes and oversized-record rejection, renegotiation ServerHello extension parsing, missing-scan comparator failures, safe OCSP AIA URL extraction across non-OCSP methods, unsupported schemes, and credential-bearing URLs, TLS Feature must-staple parsing, OCSP Stapling ServerHello and CertificateStatus framing, trust-chain issuer and CA-subject mismatch rejection, CLI help, pre-logger parse-error, and STARTTLS-only argument-validation paths, default JA3/JA3S/JARM database loading, continuation of the fingerprint phase when JA3/JA3S/JARM connections fail, certificate signature fallbacks for DER bytes, serialized metadata, and empty chains, non-UTF-8 W3C trace header rejection, and global plus owner-scoped API statistics recording. Health readiness tests also cover partial active/queued counter failures, assert that degraded status identifies the failed counter, and verify backend error text stays redacted. Prometheus scrape tests capture WARN events for active and queued scan gauge failures, validate their stable operation/error fields, and ensure backend messages are omitted. Rate-limit tests cover every health and documentation bypass path and prove those requests do not consume the authenticated caller quota. Cipher preference discovery also verifies a remote server that rejects every offered suite returns an inconclusive empty preference. Logger initialization is exercised in isolated child processes for JSON and text output, idempotent subscriber reuse when a different file destination is requested, and stderr fallback after file-destination failure. A same-process guard-drop test verifies that the structured shutdown flush event is emitted. Scanner initialization log capture explicitly propagates its dispatcher through the async future and is verified under parallel test execution. The structured unknown protocol-version warning is tested in both the application and standalone protocol crate. Both tests also exercise the captured writer flush path. ECH coverage exercises a valid HTTPS record from an isolated UDP DNS resolver and rejection of a provider without TLS 1.3 suites. Linux CI verifies rejection of persisted job files whose filename is not valid UTF-8 and runs the PostgreSQL paths against 19.0, the newest active release reported by `eol-cli`. FileJobStorage tests cover corrupt individual reads, mismatched path/payload IDs during discovery, and filesystem failures on delete and save. A focused middleware test also verifies that a valid W3C `traceparent` rejected because no OpenTelemetry layer is installed produces a redacted warning while the request succeeds. A monitor initialization test verifies structured error outcome, stage, duration, and redaction when alert-manager construction fails. A closed scan semaphore test verifies the monitor emits a structured skipped outcome and still completes the scan cycle. The invalid-domain scan-cycle test also asserts a structured target-validation failure with duration and outcome while keeping the target out of logs. Repeating a cycle before its next scheduled time is verified not to start another scan. A monitor test also verifies the alert-test API preserves each channel result independently. The CT sink path verifies discovery remains a no-op until a suffix allowlist is configured.  Loading the domain list also asserts the structured inventory event and count. The two 30-second rolling-file load tests run under `cargo llvm-cov`; regular `cargo test` continues to skip them. Multi-IP orchestration tests cover probe-only report retention and the all-failed aggregation error.  Executor clone tests verify that worker copies share shutdown and progress channels. The PQC code scanner rejects unsupported file types with a typed input error, reports invalid static regex patterns with their names, and propagates pattern-table errors. `src/pqc/scanners/code_scanner.rs` now has 100% line coverage. Directory scans recurse into source folders and exclude vendored code. A regression test verifies the scanner stops when its 10,000-file limit is exceeded. Scanner tests also verify missing-root and unreadable file/directory errors propagate. JSON output tests verify serialization failures propagate in both compact and pretty formats. Multi-IP JSON tests also verify safe handling of malformed serialized shapes; `src/output/json.rs` and `src/db/repositories/scan_repository.rs` now have 100% line coverage. The floor must rise as uncovered paths receive tests; the target is 100%. Malformed IPv6 target validation is tested for a structured warning without reflecting the supplied target.

JARM malformed probe-count tests capture and assert the structured WARN event, stable event name, and expected/actual probe counts. Remediation command tests cover the production file-output execution path, format normalization, confirmed-finding annotations, output-size limits, safe overwrite behavior, and filesystem failures. `src/commands/remediation.rs` now has 100% line coverage. Opossum tests also exercise both TLS probe paths against a local self-signed server. CT client tests cover reversed entry ranges and retry exhaustion after repeated server failures. They also verify client errors are not retried and oversized STH bodies are rejected. CT statistics tests verify bounded source tracking, overflow behavior, counter creation, and zero-rate snapshots. Compliance checker tests cover cipher allow/deny combinations, key and signature constraints, certificate validation, and expiration warnings. LDAP STARTTLS tests cover BER short/long lengths, truncated and overflowing encodings, malformed responses, and rejected server responses. Network tests cover plain-TCP passthrough when STARTTLS is disabled and typed SMTP negotiation failures. Winshock TLS record-reader tests cover complete headers and reject payload lengths that exceed the fixed buffer. DROWN record-reader tests use Tokio virtual time to cover an idle-peer timeout without a real-time delay. A scripted complete-record read also verifies the reader returns without waiting for another frame. The loopback timeout fixture synchronizes peer acceptance before teardown. Cipher phase tests verify unsupported protocols and QUIC are filtered before network probing. A closed-port case confirms failed cipher probing leaves the phase successful with no false cipher summary. Cipher aggregation tests cover matching server-order consensus, preferred-cipher agreement, and deduplication across successful backends. Cipher formatter tests cover strength colors, optional details, summary rows, and ordered protocol comparison output. Cipher preference tests parse ServerHello selections and verify malformed, truncated, or invalid cipher inputs fail safely. The Linux CI line-coverage floor is now 90.66% and will rise as uncovered paths are tested.
JARM probe tests cover empty middle-out cipher ordering, disabled ALPN, and supported-version lists without TLS 1.3.
CI runs Rust test harnesses with `RUST_TEST_THREADS=1` because tests create scoped tracing subscribers. The quality-gates script applies this default itself, including when the release workflow invokes it; dedicated logger stress tests still exercise concurrent writes and queue backpressure.
PQC scanner tests also verify the recursive walker safely ignores non-directory paths.

Recent coverage cases also verify signed webhook retries through the production URL validator and HTTP client, big-endian renegotiation write bounds including `usize` to `u32` overflow, direct rejection of unknown compliance severities, `Default` implementations for client CA and HTTP header scan phases, non-handshake records ignored while locating ServerHelloDone, empty IRC replies and final CAP LS parsing, no-data analytics ranges, zero-sample protocol trend summaries, the structured warning emitted for an unknown TLS version fallback, and early-data result analysis across confirmed, unknown-size, protected, and inconclusive replay outcomes. Vulnerability-trend tests also reject invalid time windows before querying storage. Certificate key-strength tests cover EC rejection below 224 bits, advisory suppression at 224 bits, and missing public-key size; `src/certificates/validator/key_strength.rs` now has 100% line coverage. DNS cache tests verify lookup- and capacity-triggered cleanup of expired entries. ASN/CIDR tests cover valid and empty RIPEstat prefix results, mixed local input expansion, ASN prefix casing, and lazy iteration of large networks, IPv6 single-address networks, and invalid CIDR-like hostname input. Parsed host/port/day inputs also cover valid URL forms; `src/application/parsed_input.rs` now has 100% line coverage. Hostname validation tests cover CN and SAN wildcard boundaries, malformed subjects, and missing CN values; `src/certificates/validator/hostname_match.rs` now has 100% line coverage. Trend analyses now reject persisted history rows without scan IDs instead of silently omitting samples. The ChangeTracker history API now has integration coverage for scan-pair comparison, the single-scan empty outcome, and missing scan IDs. Rating-change tests verify component and overall score direction, rationale changes, and added or removed categories. Internal rating tests verify missing scan IDs return errors and empty rating queries produce no events. The default policy adapter is fully covered, including invalid-input mapping before any network call. Vulnerability change tracking uses enumerated in-range candidate indexes directly; `src/db/analytics/change_tracker/vulnerabilities.rs` now has 100% line coverage. DNS cache tests verify lookup- and capacity-triggered cleanup of expired entries. ASN/CIDR tests cover valid and empty RIPEstat prefix results, mixed local input expansion, ASN prefix casing, and lazy iteration of large networks, IPv6 single-address networks, and invalid CIDR-like hostname input. Parsed host/port/day inputs also cover valid URL forms; `src/application/parsed_input.rs` now has 100% line coverage. IPv6 target display formatting is tested alongside DNS hostname display. JSON file writers are tested for destination-write failures and error propagation; scan-diff tests reject schema-invalid result files and verify the command name. Report formatting tests also cover all severity labels, optional old/new values, empty reports, and deterministic ordering. The scan repository test fixtures use direct SQLx pools to avoid impossible enum-unwrapping branches; a subprocess test verifies the PostgreSQL integration test skips cleanly without its URL, and SQLite and PostgreSQL repository paths pass. The `scan.phase` test runs its orchestrator future under an explicit parent span with propagated dispatch and verifies structured error outcome, duration, and secret redaction. The OTLP integration test pins `OTEL_RESOURCE_ATTRIBUTES` and asserts the exported `service.name` fallback. Scan command tests cover baseline absence, unchanged output, missing files, target mismatches, and rejection before scanning when no target is supplied; threshold tests verify confirmed findings change only successful exits. `src/commands/scan.rs`, `src/commands/scan_diff.rs`, `src/db/analytics/cipher_trend.rs`, `src/db/analytics/protocol_trend.rs`, `src/db/analytics/vulnerability_trend.rs`, and `src/protocols/renegotiation/record.rs` now have 100% line coverage. The CI line-coverage floor is 89.62%. Vulnerability change-event integration tests verify that previous and current values preserve description, CVE, and component metadata. Anycast invalid-hostname failures are tested through the public scan entry point. MX terminal summaries are tested for certificate validity and confirmed-only vulnerability counts. A loopback DNS fixture verifies that custom MX resolver answers are sorted by priority without external network access. API TLS configuration tests cover explicit provider selection, mTLS CA parsing, missing and malformed CA files, certificate/key mismatch rejection, and filesystem errors for non-UTF-8 configuration paths. IMAP and POP3 STARTTLS probe tests exercise missing and invalid greetings, missing or unsupported capability responses, truncated POP3 capability replies, missing upgrade responses, and successful negotiation without the injected login command. `src/vulnerabilities/starttls_injection/imap_probe.rs` and `src/vulnerabilities/starttls_injection/pop3_probe.rs` now have 100% line coverage. The vulnerability scan phase is also covered end to end for the no-network outcome where selected checks are explicitly disabled. PQC readiness tests also cover full and hybrid scores, PQC certificate signatures, and the legacy TLS recommendation; `src/pqc/readiness.rs` now has 100% line coverage. STARTTLS response tests also reject invalid UTF-8 input before protocol parsing. Certificate-phase tests also parse a generated PEM chain through the production certificate parser. X.509 signature tests cover valid self-signatures, mismatched issuers, malformed DER, and trailing bytes; `src/certificates/signature_verify.rs` now has 100% line coverage. Target parser tests cover missing IPv6 brackets, invalid bracket suffixes and ports, ambiguous unbracketed IPv6, malformed IPv6, bracketed IPv6 without a port, and invalid suffixes after a bracketed address. A raw TCP WebSocket test verifies that the server waits one second before closing when a peer does not complete the close handshake. A Ticketbleed integration test uses a loopback server to exercise initial and resumed ClientHello handling through the public library build. A local TLS 1.3 server exercises successful client simulation and verifies negotiated protocol, cipher, forward secrecy, duration, and certificate metadata. Lucky13 builder tests verify SMTP STARTTLS configuration, hostname/server mode, and selection of all target IP addresses; task-cancellation coverage verifies blocking-task join failures map to scanner errors, and `src/vulnerabilities/lucky13.rs` now has 100% line coverage. The closed-handshake fixture now awaits an accepted probe connection and fails on listener errors. A target with no resolved IP addresses also exercises the Lucky13 missing-probe-address error. Anycast summary tests assert rendered failed and successful IP outcomes, certificate status, protocol counts, confidence, reasons, and unique-certificate details. A fail-on-write fixture verifies errors propagate from every summary output step. WebSocket coverage also verifies periodic server pings when no progress events arrive. A global progress subscriber also recovers from a lagged broadcast and delivers the latest event. A loopback TLS 1.2 server also verifies that a successful AES128-SHA CBC handshake is classified as supported. A local TLS handshake-failure alert is classified as definitive CBC non-support. Change-tracker tests cover empty and one-scan history results and pair identical vulnerability records deterministically across scans without emitting false changes. Scan comparison tests assert unchanged, new, and resolved vulnerability categories, including duplicate records without false diffs. Scan-drift tests also verify target mismatch rejection and protocol, cipher, finding, certificate, rating, and terminal summary changes. Job storage extracts filename-stem validation so Unix tests can verify non-UTF-8 rejection on macOS as well as Linux. IDS-friendly limiter tests cover expired-window reset, rate-limit waits, fixed zero delay, and all delay bounds; `src/utils/ids_friendly.rs` now has 100% line coverage. Debian weak-key tests also assert the typed diagnostic returned for a certificate without a public key. Credential route tests exercise identifiers over the 128-byte limit, internal store-error mapping, audit-event flushing, actor/resource permissions, tenant scope, and ensure filesystem details stay out of API errors. Rotation tests also cover missing-credential errors with and without a new expiry. Stats route tests also verify tenant-scoped database failures map to an internal API error. Failed API example cleanup is asserted as structured JSON with a stable event name, error code, outcome, and no local path. Fallback SCSV ClientHello tests verify explicit SNI encoding and its omission for IP-literal targets; `src/protocols/fallback_scsv/client_hello.rs` now has 100% line coverage; impossible range-update branches were removed after proving the offsets are reserved before writing and hostname lengths are bounded. Vulnerability terminal-output tests now exercise all five severity counts, confirmed and potential findings, inline and hidden inconclusive results, empty summaries, and both hint-selection paths. JA3 tests cover empty fingerprint components, all known TLS versions and named groups, unknown group fallback, and the common-signature database. `src/fingerprint/ja3.rs` now has 100% line coverage, including file loading, JSON type errors, and both database defaults. CRL URL tests reject credentials and non-HTTP schemes and cover empty certificate DER without network access. NPN ServerHello tests verify record/handshake bounds and the 100-protocol parser limit.

Cipher strength trend analysis reports a database error for persisted scan history rows without an ID instead of silently omitting them.

The webhook retry integration test exercises the production URL validation and pinned HTTP client before verifying signed delivery, retry count, and redacted structured success logging against a local loopback server. Dedicated policy tests also reject empty, private, and mixed loopback/public DNS answers. Additional URL tests reject malformed URLs and hostnames before DNS lookup.

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

