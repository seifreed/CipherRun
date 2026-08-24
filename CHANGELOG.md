# Changelog

All notable changes to CipherRun are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Explicit finding statuses, detection methods, confidence levels, and stable finding IDs.
- Structured JSON finding evidence with limitations, references, remediation, and probe safety metadata.
- JSON Schema 1.1, compatibility policy, and versioned scan-result fixtures.
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

### Changed

- Potential BREACH, weak ROBOT, and partial Lucky13 results are distinct from confirmed vulnerabilities.

## [0.3.2] - 2026-08-23

### Added

- Rust 1.88 minimum-version and beta checks in CI.
- Version metadata for the scan result JSON contract.
- Explicit CORS origin allowlists.
- Security and coordinated disclosure policy.
- Shared CI and release quality gates for formatting, linting, tests, documentation,
  dependency policy, packaging, installation, and the production container.
- Separate hardened production and packet-capture laboratory container images.

### Changed

- API server startup now requires an explicit credentials file.
- Generated API configurations use owner-only permissions on Unix and are not overwritten.
- Query-string API keys are limited to WebSocket stream endpoints and deprecated.
- Swagger UI is disabled by default and only advertised when served.
- BREACH prerequisites are reported as potential exposure, not confirmed exploitation.
- Compliance reports state that they assess mapped TLS controls, not certification or full regulatory compliance.
- Updated `h2` to 0.4.16 to address RUSTSEC-2026-0258.
- The production container now uses a non-root distroless runtime with no shell or Linux capabilities.

## [0.3.1] - 2026-08-13

### Changed

- Bumped the release version to 0.3.1.

## [0.3.0] - 2026-08-13

### Changed

- Clarified release artifact documentation.
- Automated crates.io and multiplatform binary releases.

[Unreleased]: https://github.com/seifreed/CipherRun/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/seifreed/CipherRun/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/seifreed/CipherRun/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/seifreed/CipherRun/releases/tag/v0.3.0
