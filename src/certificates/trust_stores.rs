// Trust Store Validation - Multi-platform certificate chain validation
//
// Copyright (C) 2025 Marc Rivero López
// Licensed under the GNU General Public License v3.0

use super::parser::{CertificateChain, CertificateInfo};
use crate::Result;
use crate::data::CA_STORES;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use x509_parser::prelude::*;

/// Supported trust store platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustStore {
    /// Mozilla NSS (Firefox, Thunderbird)
    Mozilla,
    /// Apple (macOS, iOS)
    Apple,
    /// Android
    Android,
    /// Java JDK cacerts
    Java,
    /// Microsoft Windows
    Windows,
}

impl TrustStore {
    /// Get all supported trust stores
    pub fn all() -> Vec<TrustStore> {
        vec![
            TrustStore::Mozilla,
            TrustStore::Apple,
            TrustStore::Android,
            TrustStore::Java,
            TrustStore::Windows,
        ]
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            TrustStore::Mozilla => "Mozilla NSS",
            TrustStore::Apple => "Apple",
            TrustStore::Android => "Android",
            TrustStore::Java => "Java",
            TrustStore::Windows => "Microsoft Windows",
        }
    }
}

impl std::fmt::Display for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            TrustStore::Mozilla => "Mozilla",
            TrustStore::Apple => "Apple",
            TrustStore::Android => "Android",
            TrustStore::Java => "Java",
            TrustStore::Windows => "Windows",
        };
        write!(f, "{}", name)
    }
}

/// Per-platform trust validation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformTrustStatus {
    /// Platform trust store
    pub platform: TrustStore,
    /// Whether certificate chain is trusted on this platform
    pub trusted: bool,
    /// Root CA that validated the chain (if trusted)
    pub trusted_root: Option<String>,
    /// Validation message or error
    pub message: String,
    /// Additional details about validation
    pub details: ValidationDetails,
}

/// Detailed validation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationDetails {
    /// Chain verification successful
    pub chain_verified: bool,
    /// Root CA found in trust store
    pub root_in_store: bool,
    /// All signatures valid
    pub signatures_valid: bool,
    /// Trust anchor subject (root or intermediate)
    pub trust_anchor: Option<String>,
}

/// Complete trust validation result across all platforms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustValidationResult {
    /// Per-platform trust status.
    ///
    /// A `BTreeMap` (not `HashMap`) so serialized output (JSON/etc.) orders
    /// platforms deterministically by `TrustStore` instead of by random hash
    /// iteration order, which otherwise varied across runs.
    pub platform_status: BTreeMap<TrustStore, PlatformTrustStatus>,
    /// Overall trust status (trusted by at least one major platform)
    pub overall_trusted: bool,
    /// Number of platforms that trust this certificate
    pub trusted_count: usize,
    /// Total platforms checked
    pub total_platforms: usize,
    /// Per-certificate trust breakdown (role in chain + recognizing platforms)
    #[serde(default)]
    pub per_certificate: Vec<CertificateValidation>,
}

impl TrustValidationResult {
    /// Check if trusted by specific platform
    pub fn is_trusted_by(&self, platform: TrustStore) -> bool {
        self.platform_status
            .get(&platform)
            .map(|s| s.trusted)
            .unwrap_or(false)
    }

    /// Get platforms that trust this certificate, in stable `TrustStore` order.
    pub fn trusted_platforms(&self) -> Vec<TrustStore> {
        let mut platforms: Vec<TrustStore> = self
            .platform_status
            .iter()
            .filter(|(_, status)| status.trusted)
            .map(|(platform, _)| *platform)
            .collect();
        platforms.sort_unstable();
        platforms
    }

    /// Get platforms that don't trust this certificate, in stable order.
    pub fn untrusted_platforms(&self) -> Vec<TrustStore> {
        let mut platforms: Vec<TrustStore> = self
            .platform_status
            .iter()
            .filter(|(_, status)| !status.trusted)
            .map(|(platform, _)| *platform)
            .collect();
        platforms.sort_unstable();
        platforms
    }

    /// Get summary text
    pub fn summary(&self) -> String {
        if self.overall_trusted {
            format!(
                "Trusted by {}/{} platforms: {}",
                self.trusted_count,
                self.total_platforms,
                self.trusted_platforms()
                    .iter()
                    .map(|p| p.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            "Not trusted by any major platform".to_string()
        }
    }
}

/// Trust store validator - validates certificate chains against multiple platform trust stores
pub struct TrustStoreValidator {
    /// Subject Key Identifier index for fast lookups
    skid_index: HashMap<String, Vec<usize>>,
    /// Subject DN index for fallback lookups
    subject_index: HashMap<String, Vec<usize>>,
}

impl TrustStoreValidator {
    /// Create new trust store validator with optimized indexes
    pub fn new() -> Result<Self> {
        let mut validator = Self {
            skid_index: HashMap::new(),
            subject_index: HashMap::new(),
        };

        // Build indexes for fast lookups
        validator.build_indexes()?;

        Ok(validator)
    }

    /// Build SKID and Subject indexes for all CA certificates
    fn build_indexes(&mut self) -> Result<()> {
        let stores = CA_STORES.as_ref();

        for (store_idx, store) in stores.all_stores().iter().enumerate() {
            for (cert_idx, ca_cert) in store.certificates.iter().enumerate() {
                let global_idx = (store_idx << 16) | cert_idx;

                // Index by subject DN
                self.subject_index
                    .entry(ca_cert.subject.clone())
                    .or_default()
                    .push(global_idx);

                // Try to extract Subject Key Identifier for more accurate matching
                if let Ok((_, cert)) = X509Certificate::from_der(&ca_cert.der)
                    && let Ok(Some(ext)) = cert
                        .get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
                    && let ParsedExtension::SubjectKeyIdentifier(skid) = ext.parsed_extension()
                {
                    let skid_hex = hex::encode(skid.0);
                    self.skid_index
                        .entry(skid_hex)
                        .or_default()
                        .push(global_idx);
                }
            }
        }

        Ok(())
    }

    /// Validate certificate chain against all platform trust stores
    pub fn validate_chain(&self, chain: &CertificateChain) -> Result<TrustValidationResult> {
        let mut platform_status = BTreeMap::new();

        for platform in TrustStore::all() {
            let status = self.validate_against_platform(chain, platform)?;
            platform_status.insert(platform, status);
        }

        let trusted_count = platform_status.values().filter(|s| s.trusted).count();
        let total_platforms = platform_status.len();
        let overall_trusted = trusted_count > 0;
        let per_certificate = self.validate_each_certificate(chain);

        Ok(TrustValidationResult {
            platform_status,
            overall_trusted,
            trusted_count,
            total_platforms,
            per_certificate,
        })
    }

    /// Classify each certificate in the chain by role and record which platform
    /// trust stores recognize it.
    fn validate_each_certificate(&self, chain: &CertificateChain) -> Vec<CertificateValidation> {
        let last_index = chain.certificates.len().saturating_sub(1);
        chain
            .certificates
            .iter()
            .enumerate()
            .map(|(idx, cert)| {
                let role = if idx == 0 {
                    CertificateRole::Leaf
                } else if idx == last_index {
                    CertificateRole::Root
                } else {
                    CertificateRole::Intermediate
                };
                self.validate_certificate(cert, role)
            })
            .collect()
    }

    /// Validate certificate chain against a specific platform trust store
    fn validate_against_platform(
        &self,
        chain: &CertificateChain,
        platform: TrustStore,
    ) -> Result<PlatformTrustStatus> {
        // Get the appropriate CA store for this platform
        let stores = CA_STORES.as_ref();
        let ca_store = match platform {
            TrustStore::Mozilla => &stores.mozilla,
            TrustStore::Apple => &stores.apple,
            TrustStore::Android => &stores.android,
            TrustStore::Java => &stores.java,
            TrustStore::Windows => &stores.microsoft,
        };

        // Strategy: Walk the chain from leaf to root, finding trust anchor
        let mut chain_verified = false;
        let mut root_in_store = false;
        let mut trusted_root: Option<String> = None;
        let mut trust_anchor: Option<String> = None;
        let mut message = String::new();

        // Check if chain is empty
        if chain.certificates.is_empty() {
            return Ok(PlatformTrustStatus {
                platform,
                trusted: false,
                trusted_root: None,
                message: "Empty certificate chain".to_string(),
                details: ValidationDetails {
                    chain_verified: false,
                    root_in_store: false,
                    signatures_valid: false,
                    trust_anchor: None,
                },
            });
        }

        // Get the last certificate in the chain (should be root or closest to root)
        let last_cert = chain
            .certificates
            .last()
            .ok_or_else(|| crate::error::TlsError::Other("Certificate chain is empty".into()))?;

        // Check if the last cert is a self-signed root
        let is_self_signed_root = last_cert.subject == last_cert.issuer && last_cert.is_ca;

        // DER of the matched trust-anchor CA, plus whether the match was by identity
        // (the last chain cert *is* the trusted CA) or by issuance (the last chain
        // cert is *signed by* the trusted CA). This drives the crypto check below.
        let mut anchor_ca_der: Option<Vec<u8>> = None;
        let mut anchor_is_identity = false;

        if is_self_signed_root {
            // Check if this root is in the platform's trust store
            for ca_cert in &ca_store.certificates {
                if ca_cert.subject == last_cert.subject {
                    // Found matching root CA
                    chain_verified = true;
                    root_in_store = true;
                    trusted_root = Some(ca_cert.subject.clone());
                    trust_anchor = Some(ca_cert.subject.clone());
                    anchor_ca_der = Some(ca_cert.der.clone());
                    anchor_is_identity = true;
                    message = format!("Chain trusted via root CA: {}", ca_cert.subject);
                    break;
                }
            }

            if !root_in_store {
                message = format!(
                    "Self-signed root CA not found in {} trust store",
                    platform.name()
                );
            }
        } else {
            // Chain doesn't include root, check if issuer of last cert is in store
            for ca_cert in &ca_store.certificates {
                // Check if CA's subject matches the issuer of our last cert
                if ca_cert.subject == last_cert.issuer {
                    chain_verified = true;
                    root_in_store = true;
                    trusted_root = Some(ca_cert.subject.clone());
                    trust_anchor = Some(ca_cert.subject.clone());
                    anchor_ca_der = Some(ca_cert.der.clone());
                    anchor_is_identity = false;
                    message = format!("Chain trusted via root CA: {}", ca_cert.subject);
                    break;
                }

                // Also check if the last cert itself is in the store (intermediate acting as trust anchor)
                if ca_cert.subject == last_cert.subject {
                    chain_verified = true;
                    root_in_store = true;
                    trusted_root = Some(ca_cert.subject.clone());
                    trust_anchor = Some(last_cert.subject.clone());
                    anchor_ca_der = Some(ca_cert.der.clone());
                    anchor_is_identity = true;
                    message = format!("Chain trusted via intermediate CA: {}", ca_cert.subject);
                    break;
                }
            }

            if !root_in_store {
                message = format!(
                    "Issuing CA '{}' not found in {} trust store",
                    last_cert.issuer,
                    platform.name()
                );
            }
        }

        // Cryptographic signature verification. A subject/issuer name match only
        // proves a CA with that name exists; it does NOT prove the chain was signed
        // by that CA's private key. Verify every signature before trusting.
        let signatures_valid = root_in_store
            && Self::verify_chain_signatures(chain, anchor_ca_der.as_deref(), anchor_is_identity)?;

        if chain_verified && root_in_store && !signatures_valid {
            message = format!(
                "{} (signature verification failed: chain is not cryptographically signed by the trust anchor)",
                message
            );
        }

        let trusted = chain_verified && root_in_store && signatures_valid;

        Ok(PlatformTrustStatus {
            platform,
            trusted,
            trusted_root: trusted_root.clone(),
            message,
            details: ValidationDetails {
                chain_verified,
                root_in_store,
                signatures_valid,
                trust_anchor,
            },
        })
    }

    /// Cryptographically verify every signature in the chain plus the trust anchor.
    ///
    /// - Each `cert[i]` must be signed by `cert[i + 1]`.
    /// - The final chain certificate must be vouched for by the matched CA store
    ///   entry: by issuance (its signature verifies against the CA public key) when
    ///   `anchor_is_identity` is false, or by identity (it IS the stored CA, byte for
    ///   byte) when true.
    ///
    /// Returns `false` if any required DER blob is missing, since a signature that
    /// cannot be checked must not be assumed valid.
    fn verify_chain_signatures(
        chain: &CertificateChain,
        anchor_ca_der: Option<&[u8]>,
        anchor_is_identity: bool,
    ) -> crate::Result<bool> {
        use crate::certificates::signature_verify::verify_cert_signature;

        let certs = &chain.certificates;

        let Some(last_cert) = certs.last() else {
            return Ok(false);
        };

        // Internal links: cert[i] must be signed by cert[i + 1].
        for pair in certs.windows(2) {
            let [cert, issuer_cert] = pair else {
                continue;
            };
            if cert.der_bytes.is_empty() || issuer_cert.der_bytes.is_empty() {
                return Ok(false);
            }
            // The issuer must be a CA (basic constraints CA:TRUE). Without this,
            // a non-CA end-entity certificate from a trusted CA could sign a
            // forged leaf and every signature would still verify — the classic
            // basic-constraints bypass. (Mirrors the chain validator.)
            if !issuer_cert.is_ca {
                return Ok(false);
            }
            // keyUsage, when present, must permit certificate signing
            // (RFC 5280 §4.2.1.3). Mirrors the chain validator.
            if issuer_cert.key_usage_forbids_cert_signing() {
                return Ok(false);
            }
            if !verify_cert_signature(&cert.der_bytes, &issuer_cert.der_bytes)? {
                return Ok(false);
            }
        }

        // Trust anchor: the last chain cert must connect to the stored CA.
        let Some(ca_der) = anchor_ca_der else {
            return Ok(false);
        };
        if ca_der.is_empty() || last_cert.der_bytes.is_empty() {
            return Ok(false);
        }

        let valid = if anchor_is_identity {
            // The last cert IS the trusted CA: require an exact DER match so a
            // forged certificate that merely reuses the CA's name is rejected.
            last_cert.der_bytes == ca_der
        } else {
            // The last cert is issued by the trusted CA: verify its signature.
            verify_cert_signature(&last_cert.der_bytes, ca_der)?
        };
        Ok(valid)
    }

    /// Classify a single certificate: which platform trust stores contain it.
    fn validate_certificate(
        &self,
        cert: &CertificateInfo,
        role: CertificateRole,
    ) -> CertificateValidation {
        let mut platforms_recognizing = Vec::new();
        let stores = CA_STORES.as_ref();

        for platform in TrustStore::all() {
            let ca_store = match platform {
                TrustStore::Mozilla => &stores.mozilla,
                TrustStore::Apple => &stores.apple,
                TrustStore::Android => &stores.android,
                TrustStore::Java => &stores.java,
                TrustStore::Windows => &stores.microsoft,
            };

            if ca_store
                .certificates
                .iter()
                .any(|ca_cert| ca_cert.subject == cert.subject)
            {
                platforms_recognizing.push(platform);
            }
        }

        CertificateValidation {
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            role,
            in_trust_stores: !platforms_recognizing.is_empty(),
            platforms: platforms_recognizing,
        }
    }
}

/// Certificate role in the chain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateRole {
    /// End-entity (leaf) certificate
    Leaf,
    /// Intermediate CA certificate
    Intermediate,
    /// Root CA certificate
    Root,
}

/// Individual certificate validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidation {
    /// Certificate subject
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Role in certificate chain
    pub role: CertificateRole,
    /// Whether certificate is in any trust store
    pub in_trust_stores: bool,
    /// Platforms that recognize this certificate
    pub platforms: Vec<TrustStore>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_store_enum() {
        let stores = TrustStore::all();
        assert_eq!(stores.len(), 5);
        assert!(stores.contains(&TrustStore::Mozilla));
        assert!(stores.contains(&TrustStore::Apple));
        assert!(stores.contains(&TrustStore::Android));
        assert!(stores.contains(&TrustStore::Java));
        assert!(stores.contains(&TrustStore::Windows));
    }

    #[test]
    fn test_trust_store_names() {
        assert_eq!(TrustStore::Mozilla.name(), "Mozilla NSS");
        assert_eq!(TrustStore::Apple.name(), "Apple");
        assert_eq!(TrustStore::Android.name(), "Android");
        assert_eq!(TrustStore::Java.name(), "Java");
        assert_eq!(TrustStore::Windows.name(), "Microsoft Windows");
    }

    #[test]
    fn test_trust_store_display() {
        assert_eq!(format!("{}", TrustStore::Mozilla), "Mozilla");
        assert_eq!(format!("{}", TrustStore::Windows), "Windows");
    }

    #[test]
    fn test_validator_creation() {
        let validator = TrustStoreValidator::new();
        assert!(validator.is_ok());

        let validator = validator.expect("test assertion should succeed");
        // Indexes should be populated
        assert!(!validator.subject_index.is_empty());
    }

    #[test]
    fn test_empty_chain_validation() {
        let validator = TrustStoreValidator::new().expect("test assertion should succeed");

        let empty_chain = CertificateChain {
            certificates: vec![],
            chain_length: 0,
            chain_size_bytes: 0,
        };

        let result = validator.validate_chain(&empty_chain);
        assert!(result.is_ok());

        let result = result.expect("test assertion should succeed");
        assert!(!result.overall_trusted);
        assert_eq!(result.trusted_count, 0);
    }

    fn cert_with_subject(subject: &str) -> CertificateInfo {
        CertificateInfo {
            subject: subject.to_string(),
            issuer: "CN=issuer".to_string(),
            serial_number: "1".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2030-01-01".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec![],
            is_ca: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            certificate_transparency: None,
            der_bytes: vec![],
        }
    }

    #[test]
    fn test_verify_chain_signatures_rejects_non_ca_issuer() {
        // Basic-constraints bypass: a non-CA issuer must be rejected before any
        // signature check. Non-empty (garbage) DER passes the empty-DER guard so
        // the is_ca gate is what fails the chain.
        let mut leaf = cert_with_subject("CN=leaf.example.com");
        leaf.issuer = "CN=not-a-ca".to_string();
        leaf.der_bytes = vec![1, 2, 3];

        let mut issuer = cert_with_subject("CN=not-a-ca");
        issuer.der_bytes = vec![4, 5, 6];
        issuer.is_ca = false;

        let chain = CertificateChain {
            certificates: vec![leaf, issuer],
            chain_length: 2,
            chain_size_bytes: 0,
        };

        assert!(
            !TrustStoreValidator::verify_chain_signatures(&chain, Some(&[7, 8, 9]), false)
                .expect("signature verification should not error for non-CA issuer"),
            "a non-CA issuer must fail chain signature verification"
        );
    }

    #[test]
    fn test_validate_chain_classifies_certificate_roles_by_position() {
        let validator = TrustStoreValidator::new().expect("validator should initialize");
        let chain = CertificateChain {
            certificates: vec![
                cert_with_subject("CN=leaf.example.com"),
                cert_with_subject("CN=Intermediate CA"),
                cert_with_subject("CN=Root CA"),
            ],
            chain_length: 3,
            chain_size_bytes: 0,
        };

        let result = validator
            .validate_chain(&chain)
            .expect("validation should succeed");

        let roles: Vec<CertificateRole> = result.per_certificate.iter().map(|c| c.role).collect();
        assert_eq!(
            roles,
            vec![
                CertificateRole::Leaf,
                CertificateRole::Intermediate,
                CertificateRole::Root
            ]
        );
    }

    #[test]
    fn test_trust_validation_result_methods() {
        let mut platform_status = BTreeMap::new();

        platform_status.insert(
            TrustStore::Mozilla,
            PlatformTrustStatus {
                platform: TrustStore::Mozilla,
                trusted: true,
                trusted_root: Some("Root CA".to_string()),
                message: "Trusted".to_string(),
                details: ValidationDetails {
                    chain_verified: true,
                    root_in_store: true,
                    signatures_valid: true,
                    trust_anchor: Some("Root CA".to_string()),
                },
            },
        );

        platform_status.insert(
            TrustStore::Apple,
            PlatformTrustStatus {
                platform: TrustStore::Apple,
                trusted: false,
                trusted_root: None,
                message: "Not trusted".to_string(),
                details: ValidationDetails {
                    chain_verified: false,
                    root_in_store: false,
                    signatures_valid: false,
                    trust_anchor: None,
                },
            },
        );

        let result = TrustValidationResult {
            platform_status,
            overall_trusted: true,
            trusted_count: 1,
            total_platforms: 2,
            per_certificate: Vec::new(),
        };

        assert!(result.is_trusted_by(TrustStore::Mozilla));
        assert!(!result.is_trusted_by(TrustStore::Apple));

        let trusted = result.trusted_platforms();
        assert_eq!(trusted.len(), 1);
        assert!(trusted.contains(&TrustStore::Mozilla));

        let untrusted = result.untrusted_platforms();
        assert_eq!(untrusted.len(), 1);
        assert!(untrusted.contains(&TrustStore::Apple));
    }

    #[test]
    fn test_forged_self_signed_root_matching_ca_name_is_not_trusted() {
        let validator = TrustStoreValidator::new().expect("test assertion should succeed");

        let stores = CA_STORES.as_ref();
        let known_subject = stores
            .mozilla
            .certificates
            .first()
            .map(|c| c.subject.clone())
            .expect("Mozilla store should contain at least one CA");

        // A self-signed certificate that merely reuses a trusted CA's name but is
        // not the stored CA (different/garbage DER) must never be trusted.
        let forged_root = CertificateInfo {
            subject: known_subject.clone(),
            issuer: known_subject,
            is_ca: true,
            der_bytes: vec![0x30, 0x82, 0x00, 0x01],
            ..Default::default()
        };

        let chain = CertificateChain {
            certificates: vec![forged_root],
            chain_length: 1,
            chain_size_bytes: 0,
        };

        let status = validator
            .validate_against_platform(&chain, TrustStore::Mozilla)
            .expect("validation should not error");

        assert!(
            !status.trusted,
            "forged root reusing a CA name must not be trusted"
        );
        assert!(
            !status.details.signatures_valid,
            "signature verification must fail for a forged root"
        );
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_real_certificate_validation() {
        use crate::certificates::parser::CertificateParser;
        use crate::utils::network::Target;

        // Test with a well-known public certificate
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let parser = CertificateParser::new(target);
        let chain = parser
            .get_certificate_chain()
            .await
            .expect("test assertion should succeed");

        let validator = TrustStoreValidator::new().expect("test assertion should succeed");
        let result = validator
            .validate_chain(&chain)
            .expect("test assertion should succeed");

        // Google's certificate should be trusted by major platforms
        assert!(result.overall_trusted);
        assert!(result.trusted_count > 0);

        // Should be trusted by at least Mozilla and Google uses public CAs
        println!("Trust validation result: {}", result.summary());
        println!("Trusted platforms: {:?}", result.trusted_platforms());
    }
}
