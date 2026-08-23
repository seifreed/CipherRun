# CipherRun Scan Result Schemas

The current JSON output contract is schema `1.1`:

- `cipherrun-scan-1.1.schema.json` is the canonical JSON Schema.
- `../fixtures/scan-results/1.1-potential-exposure.json` is a readable fixture.
- `cargo run --example export_schema` regenerates the canonical schema from code.

## Compatibility

- Minor schema releases are additive. Consumers must ignore unknown fields.
- Existing fields keep their meaning within a major schema version.
- Removing or redefining a field requires a new major schema version.
- CipherRun currently validates both `1.0` and `1.1` inputs.
- New output uses `1.1`; legacy booleans remain for `1.0` consumers, while `status` is authoritative.
- Evidence endpoint and attempt fields may be `null` when the probe does not retain that detail. The parent scan still identifies the target, and multi-IP output provides per-IP result context.

## History

### 1.1

- Added stable `finding_id` values.
- Added explicit status, detection method, and confidence enums.
- Added structured evidence, limitations, references, remediation, and probe safety metadata.

### 1.0

- Initial versioned scan result contract.
