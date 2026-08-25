# External Security Audit Readiness

## Status

No independent third-party security audit has been completed for CipherRun
0.4.0. This document is an evidence checklist, not an audit report or a
security certification.

## Scope for an external auditor

- API authentication, credential rotation/revocation, tenant ownership, rate
  limits, CORS, forwarded-address handling, and SSRF/network policy.
- SQLite/PostgreSQL job persistence, leases, retries, dead-letter handling,
  cancellation races, retention, and worker authorization.
- TLS protocol probes, certificate parsing/validation, timing probes, and
  delegated-credential evidence boundaries.
- CLI/JSON/OpenAPI contracts, release packaging, container hardening, SBOM,
  provenance, and signing workflow.

## Reproducible pre-audit evidence

Run from the release commit:

```text
scripts/quality-gates.sh
scripts/check-stable-contracts.sh
scripts/validate-rule-pack-provenance.sh
cargo test --test api_production_server_tests --locked
make lab-validate
make external-fixture
```

The auditor should record the commit, toolchain, operating system, command
output, and SHA-256 of every uploaded transcript and release asset. Findings
must include severity, affected commit, reproduction steps, remediation, and
a verification result for the fixed commit.

## Completion criteria

The audit is complete only when an independent report is attached to the
release, its scope and exclusions are explicit, all findings have an owner and
status, and the release notes link to the report. Until then, the v1.0 audit
criterion remains open.
