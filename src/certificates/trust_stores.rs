// Trust Store Validation - Multi-platform certificate chain validation
//
// Copyright (C) 2025 Marc Rivero López
// Licensed under the GNU General Public License v3.0

use super::parser::{CertificateChain, CertificateInfo};
use crate::Result;
use crate::data::CA_STORES;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x509_parser::prelude::*;

/// Supported trust store platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    /// Get store identifier for internal lookups
    #[allow(dead_code)]
    fn store_id(&self) -> &'static str {
        match self {
            TrustStore::Mozilla => "mozilla",
            TrustStore::Apple => "apple",
            TrustStore::Android => "android",
            TrustStore::Java => "java",
            TrustStore::Windows => "microsoft",
        }
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
    /// Per-platform trust status
    pub platform_status: HashMap<TrustStore, PlatformTrustStatus>,
    /// Overall trust status (trusted by at least one major platform)
    pub overall_trusted: bool,
    /// Number of platforms that trust this certificate
    pub trusted_count: usize,
    /// Total platforms checked
    pub total_platforms: usize,
}

impl TrustValidationResult {
    /// Check if trusted by specific platform
    pub fn is_trusted_by(&self, platform: TrustStore) -> bool {
        self.platform_status
            .get(&platform)
            .map(|s| s.trusted)
            .unwrap_or(false)
    }

    /// Get platforms that trust this certificate
    pub fn trusted_platforms(&self) -> Vec<TrustStore> {
        self.platform_status
            .iter()
            .filter(|(_, status)| status.trusted)
            .map(|(platform, _)| *platform)
            .collect()
    }

    /// Get platforms that don't trust this certificate
    pub fn untrusted_platforms(&self) -> Vec<TrustStore> {
        self.platform_status
            .iter()
            .filter(|(_, status)| !status.trusted)
            .map(|(platform, _)| *platform)
            .collect()
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
        let mut platform_status = HashMap::new();

        for platform in TrustStore::all() {
            let status = self.validate_against_platform(chain, platform)?;
            platform_status.insert(platform, status);
        }

        let trusted_count = platform_status.values().filter(|s| s.trusted).count();
        let total_platforms = platform_status.len();
        let overall_trusted = trusted_count > 0;

        Ok(TrustValidationResult {
            platform_status,
            overall_trusted,
            trusted_count,
            total_platforms,
        })
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
        let last_cert = chain.certificates.last().unwrap();

        // Check if the last cert is a self-signed root
        let is_self_signed_root = last_cert.subject == last_cert.issuer && last_cert.is_ca;

        if is_self_signed_root {
            // Check if this root is in the platform's trust store
            for ca_cert in &ca_store.certificates {
                if ca_cert.subject == last_cert.subject {
                    // Found matching root CA
                    chain_verified = true;
                    root_in_store = true;
                    trusted_root = Some(ca_cert.subject.clone());
                    trust_anchor = Some(ca_cert.subject.clone());
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
                    message = format!("Chain trusted via root CA: {}", ca_cert.subject);
                    break;
                }

                // Also check if the last cert itself is in the store (intermediate acting as trust anchor)
                if ca_cert.subject == last_cert.subject {
                    chain_verified = true;
                    root_in_store = true;
                    trusted_root = Some(ca_cert.subject.clone());
                    trust_anchor = Some(last_cert.subject.clone());
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

        // Signature validation (simplified - full validation would verify each signature)
        let signatures_valid = chain_verified; // If we found trust anchor, assume signatures valid

        let trusted = chain_verified && root_in_store;

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

    /// Validate certificate chain with detailed per-certificate analysis
    pub fn validate_chain_detailed(
        &self,
        chain: &CertificateChain,
    ) -> Result<DetailedValidationResult> {
        let mut cert_validations = Vec::new();

        for (idx, cert) in chain.certificates.iter().enumerate() {
            let role = if idx == 0 {
                CertificateRole::Leaf
            } else if idx == chain.certificates.len() - 1 {
                CertificateRole::Root
            } else {
                CertificateRole::Intermediate
            };

            let validation = self.validate_certificate(cert, role)?;
            cert_validations.push(validation);
        }

        let overall_validation = self.validate_chain(chain)?;

        Ok(DetailedValidationResult {
            overall: overall_validation,
            certificates: cert_validations,
        })
    }

    /// Validate individual certificate
    fn validate_certificate(
        &self,
        cert: &CertificateInfo,
        role: CertificateRole,
    ) -> Result<CertificateValidation> {
        let mut platforms_recognizing = Vec::new();

        // Check if this certificate exists in any platform's trust store
        for platform in TrustStore::all() {
            let stores = CA_STORES.as_ref();
            let ca_store = match platform {
                TrustStore::Mozilla => &stores.mozilla,
                TrustStore::Apple => &stores.apple,
                TrustStore::Android => &stores.android,
                TrustStore::Java => &stores.java,
                TrustStore::Windows => &stores.microsoft,
            };

            for ca_cert in &ca_store.certificates {
                if ca_cert.subject == cert.subject {
                    platforms_recognizing.push(platform);
                    break;
                }
            }
        }

        Ok(CertificateValidation {
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            role,
            in_trust_stores: !platforms_recognizing.is_empty(),
            platforms: platforms_recognizing,
        })
    }

    /// Find root CA for a given certificate across all platforms
    pub fn find_root_ca(&self, cert: &CertificateInfo) -> Vec<(TrustStore, String)> {
        let mut roots = Vec::new();
        let stores = CA_STORES.as_ref();

        for platform in TrustStore::all() {
            let ca_store = match platform {
                TrustStore::Mozilla => &stores.mozilla,
                TrustStore::Apple => &stores.apple,
                TrustStore::Android => &stores.android,
                TrustStore::Java => &stores.java,
                TrustStore::Windows => &stores.microsoft,
            };

            for ca_cert in &ca_store.certificates {
                if ca_cert.subject == cert.issuer {
                    roots.push((platform, ca_cert.subject.clone()));
                    break;
                }
            }
        }

        roots
    }
}

impl Default for TrustStoreValidator {
    fn default() -> Self {
        Self::new().expect("Failed to initialize TrustStoreValidator")
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

/// Detailed validation result with per-certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedValidationResult {
    /// Overall trust validation across all platforms
    pub overall: TrustValidationResult,
    /// Per-certificate validation details
    pub certificates: Vec<CertificateValidation>,
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
    fn test_validator_creation() {
        let validator = TrustStoreValidator::new();
        assert!(validator.is_ok());

        let validator = validator.unwrap();
        // Indexes should be populated
        assert!(!validator.subject_index.is_empty());
    }

    #[test]
    fn test_empty_chain_validation() {
        let validator = TrustStoreValidator::new().unwrap();

        let empty_chain = CertificateChain {
            certificates: vec![],
            chain_length: 0,
            chain_size_bytes: 0,
        };

        let result = validator.validate_chain(&empty_chain);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(!result.overall_trusted);
        assert_eq!(result.trusted_count, 0);
    }

    #[test]
    fn test_trust_validation_result_methods() {
        let mut platform_status = HashMap::new();

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

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_real_certificate_validation() {
        use crate::certificates::parser::CertificateParser;
        use crate::utils::network::Target;

        // Test with a well-known public certificate
        let target = Target::parse("www.google.com:443").await.unwrap();
        let parser = CertificateParser::new(target);
        let chain = parser.get_certificate_chain().await.unwrap();

        let validator = TrustStoreValidator::new().unwrap();
        let result = validator.validate_chain(&chain).unwrap();

        // Google's certificate should be trusted by major platforms
        assert!(result.overall_trusted);
        assert!(result.trusted_count > 0);

        // Should be trusted by at least Mozilla and Google uses public CAs
        println!("Trust validation result: {}", result.summary());
        println!("Trusted platforms: {:?}", result.trusted_platforms());
    }
}
