# Changelog

All notable changes to CipherRun are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Explicit finding statuses, detection methods, confidence levels, and stable finding IDs.

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
