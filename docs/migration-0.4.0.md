# Migrating to CipherRun 0.4.0

CipherRun 0.4.0 introduces breaking changes to the Rust API, the scan-result
contract, and API-server bootstrap. Apply these changes before upgrading a
production integration.

## Rust and packages

- Rust 1.88 or newer is required (`rust-version = "1.88"`).
- The workspace is split into publishable protocol, policy, data, probes,
  server, CLI, core, and worker crates.
- Run `cargo check --locked --all-targets` and the feature checks used by your
  deployment before upgrading.

## Scan results

`ScanResults` now carries schema and scanner metadata. Consumers must read
`schema_version` and reject or quarantine unknown major schema versions.

Vulnerability results no longer use a boolean as the complete finding state.
Handle `status`, `detection_method`, `confidence`, structured `evidence`, and
`limitations`. In particular, `potential_exposure` and `inconclusive` must not
be rendered as confirmed vulnerabilities.

Use `cipherrun schema` to obtain the bundled JSON Schema. The supported
machine-readable exports are JSON, SARIF 2.1.0, and JUnit XML. Automation can
use `cipherrun diff`, `--baseline`, `--fail-on`, and the stable exit codes
documented in `docs/stability-policy.md`.

## API server

The server refuses to start without an explicit credentials file. Generate one
with `cipherrun --api-config-example` (or the equivalent deployment command),
move the one-time token into a secret manager, and keep the configuration and
token files owner-readable only.

Query-string API keys are deprecated and accepted only for the WebSocket stream
transition path. New clients must use `Authorization: Bearer` or `X-API-Key`,
then obtain a single-use 60-second ticket from
`POST /api/v1/scan/{id}/stream-ticket`.

Scan, history, inventory, policy, and statistics responses are subject to the
authenticated principal and tenant. Do not assume that a resource UUID grants
access to another principal's data.

## Jobs and workers

The development default remains in-memory. Production deployments should set
`job_storage_dir` for durable standalone recovery or select the SQLite/PostgreSQL
job backend. Distributed workers require `job_backend = "database"` and
`local_executor = false`.

## Network policy

Local CLI scans of private networks require `--allow-private` and, where
appropriate, `--allow-cidr`. API deployments retain administrator-controlled
CIDR scopes and DNS revalidation; do not replace them with a global private-IP
allow switch.

## Compatibility checklist

1. Update Rust and regenerate clients from the current OpenAPI contract.
2. Add schema-version handling and map all finding statuses explicitly.
3. Replace query-string API keys with bearer authentication and stream tickets.
4. Configure credentials, job persistence, retention, and tenant identity.
5. Run the differential fixture and package smoke checks before rollout.
