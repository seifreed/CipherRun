# Support Matrix

This matrix describes the support boundary for the 0.4 release line.

| Area | Supported | Notes |
| --- | --- | --- |
| Rust toolchain | Rust 1.88 and newer | 1.88 is the declared MSRV; stable and beta are exercised in CI. |
| Linux | x86_64, aarch64 | GNU Linux release archives and production container. |
| macOS | x86_64, aarch64 | Release archives are built on the supported macOS runners. |
| Windows | x86_64, aarch64 | MSVC release archives. |
| Scan-result JSON | Schema 1.1 | Consumers must handle unknown minor fields and reject unknown major versions. |
| SARIF | 2.1.0 | Intended for CI/security tooling ingestion. |
| JUnit XML | Current 0.4 exporter | Treat the output as an integration format, not a Rust API. |
| CLI exit codes | 0, 1, 2, 3, 4 | Defined in `docs/stability-policy.md`. |
| API | OpenAPI generated from the 0.4 server | Authentication and ownership rules are part of the contract. |
| Job storage | In-memory, file-backed, SQLite, PostgreSQL | In-memory is development-only. |
| TLS providers | rustls, optional OpenSSL legacy feature | Feature selection changes the build surface. |

## Version support

- `0.4.x`: current release line; security fixes and regressions are accepted.
- `0.3.x`: security fixes only while the 0.4 migration window remains open.
- Older versions: unsupported.

Security reports follow [SECURITY.md](../SECURITY.md). A support statement is
not a certification or a promise that every operating-system vendor's TLS
provider behaves identically.
