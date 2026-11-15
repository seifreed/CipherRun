# Migrating to CipherRun 0.5.0

CipherRun 0.5.0 updates the supported runtime floors and replaces the YAML
parser. Review the Rust API and Python SDK changes before upgrading.

## Runtime requirements

- Rust 1.89 or newer is required by the root crate and standalone worker.
- Python SDK 0.5.0 requires Python 3.10 or newer. Development tooling uses
  Python 3.11 or newer.

## Rust API

The compliance `Rule.custom_params` field now uses
`HashMap<String, serde_json::Value>`. Update code that names
`serde_yaml::Value` explicitly. The field supports JSON-compatible nested
values; arbitrary YAML constructs such as non-string mapping keys are not
represented by this type.

YAML is parsed with `serde-saphyr`. Review custom policy and compliance files
that rely on parser-specific behavior, duplicate mapping keys, implicit nulls,
or non-JSON values. Run the policy and compliance tests against deployed rule
packs before rollout.

## Python SDK

Install the new package version and use a Python 3.10+ interpreter:

```sh
python -m pip install --upgrade cipherrun-client==0.5.0
```

The dependency floor now excludes vulnerable `urllib3`, `pytest`, `virtualenv`,
`filelock`, and `zipp` releases. Rebuild environments from the updated
`requirements.txt` or package metadata.

## Validation

Run `cargo check --locked --all-features`, `cargo test --all-features`, and the
SDK tests under the minimum supported Python version before deployment.
