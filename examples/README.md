# CipherRun Examples

This directory contains example programs demonstrating various CipherRun features.

## Running Examples

```bash
# Run JA3 fingerprinting demo
cargo run --example ja3_demo
```

## Available Examples

### ja3_demo.rs

Demonstrates JA3 TLS client fingerprinting:

- Creating synthetic ClientHello messages
- Generating JA3 fingerprints
- GREASE value filtering
- Signature database matching
- Identifying different clients (Chrome, Firefox, etc.)

**Usage:**
```bash
cargo run --example ja3_demo
```

**Expected Output:**
```
=== JA3 TLS Client Fingerprinting Demo ===

Demo 1: Chrome-like TLS Fingerprint
  JA3 Hash:       [32-character MD5 hash]
  SSL Version:    TLS 1.2 (771)
  Cipher Suites:  7 suites
  Extensions:     5 extensions
  Curves:         2 curves

  JA3 String:
  771,4865-4866-4867-49199-49195-49196-49200,0-10-11-13-43,29-23,0

...
```

## Building Examples

All examples are built automatically with:

```bash
cargo build --examples
```

## Adding New Examples

1. Create a new `.rs` file in this directory
2. Add it to the table above
3. Ensure it demonstrates a specific feature clearly
4. Include comments explaining what's happening
