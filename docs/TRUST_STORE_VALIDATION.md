# Trust Store Validation System

**Copyright (C) 2025 Marc Rivero López**
**Licensed under the GNU General Public License v3.0**

## Overview

CipherRun's Trust Store Validation system validates certificate chains against multiple platform trust stores, providing comprehensive insights into which platforms trust a given certificate. This enables security professionals to identify certificates that may be trusted on some platforms but not others.

## Supported Trust Stores

The system validates certificates against five major platform trust stores:

1. **Mozilla NSS** - Used by Firefox, Thunderbird, and many Linux applications
2. **Apple** - macOS and iOS system trust store
3. **Android** - Android OS trust store
4. **Java** - JDK cacerts keystore
5. **Microsoft Windows** - Windows system certificate store

## Architecture

### Core Components

```
src/certificates/trust_stores.rs    - Multi-platform validation logic
src/certificates/validator.rs       - Integration with existing validator
src/data/ca_stores.rs               - CA certificate store loader
data/*.pem                          - Embedded trust store PEM files
scripts/update-trust-stores.sh      - Trust store update utility
```

### Key Data Structures

#### TrustStore Enum

Represents the supported platform trust stores:

```rust
pub enum TrustStore {
    Mozilla,
    Apple,
    Android,
    Java,
    Windows,
}
```

#### TrustValidationResult

Contains per-platform trust validation results:

```rust
pub struct TrustValidationResult {
    pub platform_status: HashMap<TrustStore, PlatformTrustStatus>,
    pub overall_trusted: bool,
    pub trusted_count: usize,
    pub total_platforms: usize,
}
```

#### PlatformTrustStatus

Per-platform validation status:

```rust
pub struct PlatformTrustStatus {
    pub platform: TrustStore,
    pub trusted: bool,
    pub trusted_root: Option<String>,
    pub message: String,
    pub details: ValidationDetails,
}
```

## Usage Examples

### Basic Trust Validation

```rust
use cipherrun::certificates::parser::CertificateParser;
use cipherrun::certificates::trust_stores::TrustStoreValidator;
use cipherrun::utils::network::Target;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse target and get certificate chain
    let target = Target::parse("example.com:443").await?;
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await?;

    // Validate against all platform trust stores
    let validator = TrustStoreValidator::new()?;
    let result = validator.validate_chain(&chain)?;

    // Check overall trust status
    if result.overall_trusted {
        println!("Certificate is trusted by {}/{} platforms",
                 result.trusted_count, result.total_platforms);
    } else {
        println!("Certificate is not trusted by any platform");
    }

    // Check specific platform
    if result.is_trusted_by(TrustStore::Mozilla) {
        println!("Trusted by Mozilla");
    }

    // List all trusted platforms
    for platform in result.trusted_platforms() {
        println!("Trusted by: {}", platform.name());
    }

    Ok(())
}
```

### Integrated Validation

Using the integrated validator with platform trust:

```rust
use cipherrun::certificates::parser::CertificateParser;
use cipherrun::certificates::validator::CertificateValidator;
use cipherrun::utils::network::Target;

#[tokio::main]
async fn main() -> Result<()> {
    let target = Target::parse("example.com:443").await?;
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await?;

    // Create validator with platform trust enabled
    let validator = CertificateValidator::with_platform_trust("example.com".to_string())?;
    let result = validator.validate_chain(&chain)?;

    // Standard validation results
    println!("Valid: {}", result.valid);
    println!("Hostname match: {}", result.hostname_match);
    println!("Not expired: {}", result.not_expired);

    // Platform trust results
    if let Some(platform_trust) = result.platform_trust {
        println!("Platform trust: {}", platform_trust.summary());
    }

    Ok(())
}
```

### Detailed Chain Analysis

Analyze each certificate in the chain:

```rust
use cipherrun::certificates::parser::CertificateParser;
use cipherrun::certificates::trust_stores::TrustStoreValidator;
use cipherrun::utils::network::Target;

#[tokio::main]
async fn main() -> Result<()> {
    let target = Target::parse("example.com:443").await?;
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await?;

    let validator = TrustStoreValidator::new()?;
    let result = validator.validate_chain_detailed(&chain)?;

    // Overall validation
    println!("Overall: {}", result.overall.summary());

    // Per-certificate analysis
    for cert_val in &result.certificates {
        println!("\nCertificate: {}", cert_val.subject);
        println!("  Role: {:?}", cert_val.role);
        println!("  In trust stores: {}", cert_val.in_trust_stores);
        if !cert_val.platforms.is_empty() {
            println!("  Recognized by:");
            for platform in &cert_val.platforms {
                println!("    - {}", platform.name());
            }
        }
    }

    Ok(())
}
```

### Finding Root CA

Find which root CA issued a certificate:

```rust
use cipherrun::certificates::parser::CertificateParser;
use cipherrun::certificates::trust_stores::TrustStoreValidator;
use cipherrun::utils::network::Target;

#[tokio::main]
async fn main() -> Result<()> {
    let target = Target::parse("example.com:443").await?;
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await?;

    let validator = TrustStoreValidator::new()?;

    if let Some(leaf) = chain.leaf() {
        let roots = validator.find_root_ca(leaf);

        println!("Root CAs for this certificate:");
        for (platform, root_subject) in roots {
            println!("  {}: {}", platform.name(), root_subject);
        }
    }

    Ok(())
}
```

### Per-Platform Status

Check detailed status for each platform:

```rust
use cipherrun::certificates::parser::CertificateParser;
use cipherrun::certificates::trust_stores::{TrustStore, TrustStoreValidator};
use cipherrun::utils::network::Target;

#[tokio::main]
async fn main() -> Result<()> {
    let target = Target::parse("example.com:443").await?;
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await?;

    let validator = TrustStoreValidator::new()?;
    let result = validator.validate_chain(&chain)?;

    // Iterate through all platforms
    for platform in TrustStore::all() {
        let status = result.platform_status.get(&platform).unwrap();

        println!("Platform: {}", platform.name());
        println!("  Trusted: {}", status.trusted);

        if status.trusted {
            println!("  Root CA: {}", status.trusted_root.as_ref().unwrap());
        } else {
            println!("  Message: {}", status.message);
        }

        println!("  Chain verified: {}", status.details.chain_verified);
        println!("  Root in store: {}", status.details.root_in_store);
        println!("  Signatures valid: {}", status.details.signatures_valid);
    }

    Ok(())
}
```

## Trust Store Data Management

### Embedded Trust Stores

Trust stores are embedded in the binary at compile time for portability:

- `data/Mozilla.pem` - Mozilla NSS root certificates
- `data/Apple.pem` - Apple root certificates
- `data/Android.pem` - Android root certificates
- `data/Java.pem` - Java JDK root certificates
- `data/Microsoft.pem` - Windows root certificates

### Updating Trust Stores

Use the provided script to update trust store data:

```bash
# Update all trust stores
./scripts/update-trust-stores.sh all

# Update specific trust store
./scripts/update-trust-stores.sh mozilla
./scripts/update-trust-stores.sh apple
./scripts/update-trust-stores.sh android
./scripts/update-trust-stores.sh java
./scripts/update-trust-stores.sh windows
```

#### Update Script Features

- **Mozilla**: Downloads from CCADB (Common CA Database)
- **Apple**: Extracts from macOS system bundle (on macOS)
- **Android**: Uses Mozilla baseline (AOSP sources documented)
- **Java**: Extracts from JDK cacerts keystore
- **Windows**: Exports from Windows certificate store (on Windows)

#### Manual Updates

For manual updates or custom trust stores:

1. Download root CA certificates in PEM format
2. Concatenate all certificates into a single file
3. Place in `data/<Platform>.pem`
4. Rebuild the project

Example:

```bash
# Download Mozilla root certificates
curl -o data/Mozilla.pem \
  "https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"

# Rebuild
cargo build --release
```

## Performance Optimization

The system includes several performance optimizations:

### Subject Key Identifier (SKID) Indexing

The validator builds indexes at initialization for fast lookups:

- **SKID Index**: Maps Subject Key Identifiers to CA certificates
- **Subject DN Index**: Fallback index using certificate subject names

This reduces validation time from O(n*m) to O(log n) for trust chain lookups, where n is the number of root CAs.

### Lazy Static Initialization

CA stores are loaded once at program startup using lazy_static:

```rust
lazy_static! {
    pub static ref CA_STORES: Arc<CAStores> = Arc::new(
        CAStores::load().expect("Failed to load CA stores")
    );
}
```

### Embedded Data

Trust stores are embedded at compile time using `include_str!()`, eliminating file I/O at runtime.

## Validation Algorithm

### Chain Walking Strategy

1. **Extract Last Certificate**: Get the last certificate in the chain (closest to root)
2. **Self-Signed Root Check**: Check if it's a self-signed root CA
3. **Trust Store Lookup**: Search for matching root CA in platform trust store
4. **Intermediate Check**: If not found, check if issuer is in trust store
5. **Signature Verification**: Verify signature chain (simplified in current implementation)
6. **Result Aggregation**: Combine results across all platforms

### Trust Determination

A certificate is considered trusted by a platform if:

1. The root CA in the chain exists in the platform's trust store, OR
2. The issuing CA of the last certificate exists in the trust store, OR
3. An intermediate CA acting as trust anchor exists in the store

## Security Considerations

### Trust Store Integrity

- Trust stores should be updated regularly to reflect CA removals and additions
- Verify downloaded trust store data before deployment
- Use official sources for trust store updates

### Certificate Revocation

This system validates trust chain membership but does not check revocation status. Use the separate revocation checking modules (`src/certificates/revocation.rs`) for OCSP and CRL validation.

### Signature Verification

The current implementation performs basic trust chain validation. Full cryptographic signature verification of each certificate in the chain can be enabled for enhanced security.

## Testing

### Unit Tests

Run unit tests:

```bash
cargo test trust_stores
```

### Integration Tests

Run integration tests (requires network):

```bash
cargo test --test trust_store_validation_tests -- --ignored
```

### Test Coverage

The test suite includes:

- Empty chain handling
- Single certificate validation
- Multi-certificate chain validation
- Per-platform trust status
- Real-world certificate validation (Google, GitHub, etc.)
- Edge cases (self-signed, expired, etc.)

## API Reference

### TrustStoreValidator

```rust
impl TrustStoreValidator {
    pub fn new() -> Result<Self>
    pub fn validate_chain(&self, chain: &CertificateChain) -> Result<TrustValidationResult>
    pub fn validate_chain_detailed(&self, chain: &CertificateChain) -> Result<DetailedValidationResult>
    pub fn validate_against_platform(&self, chain: &CertificateChain, platform: TrustStore) -> Result<PlatformTrustStatus>
    pub fn find_root_ca(&self, cert: &CertificateInfo) -> Vec<(TrustStore, String)>
}
```

### TrustValidationResult

```rust
impl TrustValidationResult {
    pub fn is_trusted_by(&self, platform: TrustStore) -> bool
    pub fn trusted_platforms(&self) -> Vec<TrustStore>
    pub fn untrusted_platforms(&self) -> Vec<TrustStore>
    pub fn summary(&self) -> String
}
```

### CertificateValidator

```rust
impl CertificateValidator {
    pub fn with_platform_trust(hostname: String) -> Result<Self>
    pub fn with_config(hostname: String, skip_warnings: bool, enable_platform_trust: bool) -> Result<Self>
}
```

## Troubleshooting

### Common Issues

**Issue**: Trust stores fail to load

```
Error: Failed to load CA stores
```

**Solution**: Ensure all PEM files exist in `data/` directory:
- Mozilla.pem
- Apple.pem
- Android.pem
- Java.pem
- Microsoft.pem

**Issue**: All platforms report "not trusted" for valid certificate

**Solution**:
1. Update trust stores: `./scripts/update-trust-stores.sh all`
2. Verify certificate chain is complete
3. Check that certificate hasn't been revoked

**Issue**: Build fails with "include_str!" error

**Solution**: Ensure PEM files are present before compilation. Use the update script to download them.

## Extending the System

### Adding a New Trust Store

1. Create PEM file: `data/NewPlatform.pem`
2. Update `TrustStore` enum in `trust_stores.rs`
3. Add to `CAStores` struct in `ca_stores.rs`
4. Update `validate_against_platform()` match statement
5. Update tests

### Custom Validation Logic

Extend `TrustStoreValidator` with custom validation:

```rust
impl TrustStoreValidator {
    pub fn validate_custom(&self, chain: &CertificateChain, custom_roots: &[CACertificate]) -> Result<bool> {
        // Custom validation logic
        Ok(true)
    }
}
```

## License

This Trust Store Validation System is part of CipherRun and is licensed under the GNU General Public License v3.0.

All derivative works must:
1. Attribute authorship to Marc Rivero López
2. Be distributed under the same GPLv3 license
3. Publish modified source code if redistributed publicly

See LICENSE file for full terms.

## References

- [Mozilla Root Store Policy](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/)
- [Apple Root Certificates](https://support.apple.com/en-us/HT213464)
- [Android CA Certificates](https://android.googlesource.com/platform/system/ca-certificates/)
- [Java cacerts Documentation](https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html)
- [Windows Certificate Store](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores)
- [RFC 5280 - X.509 Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [Common CA Database (CCADB)](https://www.ccadb.org/)
