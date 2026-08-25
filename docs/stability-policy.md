# Stability And Deprecation Policy

CipherRun 0.4 versions its machine-facing contracts independently. A contract
is considered stable for automation when it has a schema or generated contract,
compatibility tests, and a documented migration path.

## Contract levels

| Contract | 0.4 policy |
| --- | --- |
| CLI flags and subcommands | Additive changes are allowed; removals require a deprecation cycle. |
| Exit codes | Stable: `0` success, `1` operational/partial failure, `2` finding threshold, `3` policy failure, `4` drift. |
| Scan-result JSON | Schema 1.x is additive within the major version; unknown major versions must be rejected. |
| SARIF and JUnit | Export formats follow their upstream specifications; CipherRun-specific fields may be additive. |
| OpenAPI | The generated document is the API source of truth; breaking route or security changes require migration notes. |
| Rust crates | Semver governs public Rust APIs; `cargo semver-checks` is a release gate. |

## Deprecation rules

1. Mark the old flag, field, route, or transport in documentation and runtime
   warnings where a warning channel exists.
2. Keep the deprecated behavior for at least one minor release unless it is a
   security risk.
3. Add a migration example and a changelog entry before removal.
4. Remove the behavior only in a planned breaking release and update the
   compatibility fixtures.

Security-sensitive transports may be restricted immediately. Query-string API
keys are the current example: they remain available only for the WebSocket
transition endpoint and must be replaced with short-lived stream tickets.

## Release evidence

A release claiming a stable contract must include the schema, OpenAPI export,
package smoke checks, compatibility fixtures, checksums, and the support matrix.
The differential validation matrix is a separate evidence gate and must not be
represented as proof of implementation-level CVE exploitation.
