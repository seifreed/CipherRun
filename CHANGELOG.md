# Changelog

All notable changes to CipherRun are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes.

## [0.4.0] - 2026-08-25

### Added

- Explicit finding statuses, detection methods, confidence levels, and stable finding IDs.
- Structured JSON finding evidence with limitations, references, remediation, and probe safety metadata.
- JSON Schema 1.1, compatibility policy, and versioned scan-result fixtures.
- `cipherrun schema` exports the versioned scan-result contract, also published under `docs/`.
- CT streaming can optionally feed an allowlisted monitoring scheduler for automatic scan and alerting.
- SARIF 2.1.0 and JUnit XML exports for CI systems.
- Stable automation exit codes, `--fail-on`, and the `--fail-on-policy` alias.
- Semantic `cipherrun diff` for versioned scan-result files.
- Single-target baseline drift detection with `--baseline`.
- Explicit local CLI private-network policy with `--allow-private` and CIDR-scoped exceptions.
- Safe, standard, and aggressive scan intensity profiles.
- Independently versioned compliance rule packs with primary sources and content hashes.
- Per-IP finding evidence now records the affected address, port, and SNI in multi-IP JSON.
- Published timing methodology with median, p95, standard error, and 95% confidence intervals.
- Reproducible weak/modern TLS fixtures and differential scanner validation in the lab image.
- Per-credential scan ownership with non-secret key identifiers and cross-owner access denial.
- Hashed API credential records with explicit identity, tenant, lifecycle, and expiry metadata.
- Connected durable file job storage with restart recovery to the standalone API server.
- Principal-scoped atomic scan idempotency via the `Idempotency-Key` request header.
- Configurable terminal-job TTL with startup and periodic persisted-artifact cleanup.
- Signed, scan-bound, single-use WebSocket tickets with 60-second expiry.
- HMAC-signed scan webhooks with stable delivery IDs and bounded transient retries.
- Prometheus text metrics and per-response request IDs for operational tracing.
- Bounded structured request audit events that omit query strings and bodies.
- Request quotas are shared by credentials within the same configured tenant.
- Optional native HTTPS listener with paired certificate and private-key files.
- Optional client-certificate verification through a configured TLS CA bundle.
- SQLite/PostgreSQL job backend with conditional claims and lease recovery.
- Database job lease heartbeats, bounded scan retries, and dead-letter records.
- Standalone SQL-backed workers for distributed scan execution, with API-only
  mode guarded by `local_executor = false` and the database job backend.
- Optional OpenTelemetry OTLP tracing through the `otel` feature.
- Administrator-owned worker CIDR scopes enforced after DNS resolution.
- Scheduled Kani formal verification for the existing proof harnesses.
- Native HTTPS responses now include a one-year HSTS policy.
- Forwarded client addresses are trusted only from configured proxy CIDRs.
- Certificate inventory routes are restricted to administrator credentials until
  persisted certificate records carry tenant ownership.
- Global history and statistics routes are restricted to administrator credentials
  until persisted analytics records carry tenant ownership.

### Changed

- Potential BREACH, weak ROBOT, and partial Lucky13 results are distinct from confirmed vulnerabilities.

## [0.3.1] - 2026-08-13

### Changed

- Bumped the release version to 0.3.1.

## [0.3.0] - 2026-08-13

### Changed

- Clarified release artifact documentation.
- Automated crates.io and multiplatform binary releases.

[Unreleased]: https://github.com/seifreed/CipherRun/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/seifreed/CipherRun/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/seifreed/CipherRun/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/seifreed/CipherRun/releases/tag/v0.3.0
