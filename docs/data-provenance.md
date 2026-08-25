# Data Provenance

CipherRun treats bundled trust stores, fingerprints, and compliance rule packs
as versioned input data rather than anonymous generated files.

## Trust stores

Run `scripts/update-trust-stores.sh [mozilla|apple|android|java|windows|all]`.
Use the `manifest` target to record provenance for the checked-in baseline
without downloading a platform store.
The script writes `data/trust-stores-manifest.json` (or the path supplied by
`CIPHERRUN_TRUST_MANIFEST`) with the update target, repository revision, source
URL or local source description, certificate count, and SHA-256 for every
available PEM store, plus the extraction method. Baseline copies are recorded
as such by their method and must not be presented as native platform exports.

`.github/workflows/data-provenance.yml` runs the Mozilla refresh weekly and
opens a pull request only when tracked data changes. Other trust stores can be
selected with `workflow_dispatch`; the large Debian fingerprint corpus is
explicitly opt-in because rebuilding it downloads roughly 1 GB of source data.

## Fingerprints

`scripts/gen_debian_blacklist.sh` records the exact upstream Git revision,
generation time, entry count, and SHA-256 in
`data/debian_blacklist.meta.json` beside the generated fingerprint corpus.

## Compliance rule packs

`scripts/validate-rule-pack-provenance.sh` validates the required publication
and review metadata in every `data/compliance/*.yaml` file and emits a manifest
with the exact YAML SHA-256. It runs as part of `scripts/quality-gates.sh`.
The API exposes the same content digest and source metadata with compliance
responses, allowing a stored report to be tied back to the loaded rule pack.
