// Trust Store Validation Integration Tests
//
// Copyright (C) 2025 Marc Rivero López
// Licensed under the GNU General Public License v3.0

use cipherrun::certificates::parser::{CertificateChain, CertificateParser};
use cipherrun::certificates::trust_stores::{TrustStore, TrustStoreValidator};
use cipherrun::certificates::validator::CertificateValidator;
use cipherrun::utils::network::Target;

#[tokio::test]
#[ignore] // Requires network access
async fn test_google_certificate_multi_platform_trust() {
    // Test with Google's certificate, which should be trusted by all major platforms
    let target = Target::parse("www.google.com:443").await.unwrap();
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await.unwrap();

    let validator = TrustStoreValidator::new().unwrap();
    let result = validator.validate_chain(&chain).unwrap();

    // Google should be trusted by major platforms
    assert!(result.overall_trusted, "Google should be trusted");
    assert!(
        result.trusted_count > 0,
        "Should be trusted by at least one platform"
    );

    // Check specific platforms
    println!("Google certificate trust status:");
    for platform in TrustStore::all() {
        let status = result.platform_status.get(&platform).unwrap();
        println!(
            "  {}: {}",
            platform.name(),
            if status.trusted {
                "TRUSTED"
            } else {
                "NOT TRUSTED"
            }
        );
        if status.trusted {
            println!(
                "    Root: {}",
                status
                    .trusted_root
                    .as_ref()
                    .unwrap_or(&"Unknown".to_string())
            );
        } else {
            println!("    Message: {}", status.message);
        }
    }

    // Google typically uses public CAs trusted by Mozilla
    assert!(
        result.is_trusted_by(TrustStore::Mozilla),
        "Google should be trusted by Mozilla"
    );
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_github_certificate_multi_platform_trust() {
    let target = Target::parse("github.com:443").await.unwrap();
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await.unwrap();

    let validator = TrustStoreValidator::new().unwrap();
    let result = validator.validate_chain(&chain).unwrap();

    assert!(result.overall_trusted, "GitHub should be trusted");
    println!(
        "GitHub certificate trusted by {} platforms",
        result.trusted_count
    );
}

#[test]
fn test_trust_store_validator_initialization() {
    let validator = TrustStoreValidator::new();
    assert!(
        validator.is_ok(),
        "Validator should initialize successfully"
    );

    let _validator = validator.unwrap();
    // Indexes should be built
    println!("Trust store validator initialized with indexes");
}

#[test]
fn test_certificate_validator_with_platform_trust() {
    let validator = CertificateValidator::with_platform_trust("example.com".to_string());
    assert!(
        validator.is_ok(),
        "Should create validator with platform trust enabled"
    );
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_detailed_chain_validation() {
    let target = Target::parse("www.cloudflare.com:443").await.unwrap();
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await.unwrap();

    let validator = TrustStoreValidator::new().unwrap();
    let result = validator.validate_chain_detailed(&chain).unwrap();

    println!("Detailed validation for Cloudflare:");
    println!("Overall: {}", result.overall.summary());
    println!("\nPer-certificate analysis:");
    for cert_val in &result.certificates {
        println!("  Subject: {}", cert_val.subject);
        println!("  Role: {:?}", cert_val.role);
        println!("  In trust stores: {}", cert_val.in_trust_stores);
        if !cert_val.platforms.is_empty() {
            println!("  Recognized by: {:?}", cert_val.platforms);
        }
    }
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_integrated_validation_with_platform_trust() {
    let target = Target::parse("www.mozilla.org:443").await.unwrap();
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await.unwrap();

    // Use the integrated validator with platform trust enabled
    let validator =
        CertificateValidator::with_platform_trust("www.mozilla.org".to_string()).unwrap();
    let result = validator.validate_chain(&chain).unwrap();

    // Check that platform trust validation was performed
    assert!(
        result.platform_trust.is_some(),
        "Platform trust should be validated"
    );

    let platform_trust = result.platform_trust.as_ref().unwrap();
    println!("Mozilla.org validation:");
    println!("  Overall valid: {}", result.valid);
    println!("  Trust chain valid: {}", result.trust_chain_valid);
    println!("  Platform trust: {}", platform_trust.summary());

    if platform_trust.overall_trusted {
        println!("  Trusted by: {:?}", platform_trust.trusted_platforms());
    }
}

#[test]
fn test_trust_store_enumeration() {
    let stores = TrustStore::all();
    assert_eq!(stores.len(), 5, "Should have 5 trust stores");

    // Check all stores are present
    assert!(stores.contains(&TrustStore::Mozilla));
    assert!(stores.contains(&TrustStore::Apple));
    assert!(stores.contains(&TrustStore::Android));
    assert!(stores.contains(&TrustStore::Java));
    assert!(stores.contains(&TrustStore::Windows));

    // Check names
    for store in stores {
        let name = store.name();
        assert!(!name.is_empty(), "Store name should not be empty");
        println!("Trust store: {}", name);
    }
}

#[test]
fn test_empty_chain_validation() {
    let validator = TrustStoreValidator::new().unwrap();

    let empty_chain = CertificateChain {
        certificates: vec![],
        chain_length: 0,
        chain_size_bytes: 0,
    };

    let result = validator.validate_chain(&empty_chain).unwrap();

    assert!(!result.overall_trusted, "Empty chain should not be trusted");
    assert_eq!(
        result.trusted_count, 0,
        "Empty chain should have 0 trusted platforms"
    );

    // All platforms should reject empty chain
    for platform in TrustStore::all() {
        let status = result.platform_status.get(&platform).unwrap();
        assert!(
            !status.trusted,
            "Platform {} should not trust empty chain",
            platform.name()
        );
    }
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_find_root_ca() {
    let target = Target::parse("www.amazon.com:443").await.unwrap();
    let parser = CertificateParser::new(target);
    let chain = parser.get_certificate_chain().await.unwrap();

    let validator = TrustStoreValidator::new().unwrap();

    if let Some(leaf) = chain.leaf() {
        let roots = validator.find_root_ca(leaf);
        println!("Root CAs for Amazon leaf certificate:");
        for (platform, root_subject) in &roots {
            println!("  {}: {}", platform.name(), root_subject);
        }

        assert!(!roots.is_empty(), "Should find at least one root CA");
    }
}

#[test]
fn test_trust_validation_result_methods() {
    use cipherrun::certificates::trust_stores::{PlatformTrustStatus, ValidationDetails};
    use std::collections::HashMap;

    let mut platform_status = HashMap::new();

    // Mozilla trusts
    platform_status.insert(
        TrustStore::Mozilla,
        PlatformTrustStatus {
            platform: TrustStore::Mozilla,
            trusted: true,
            trusted_root: Some("Test Root CA".to_string()),
            message: "Trusted".to_string(),
            details: ValidationDetails {
                chain_verified: true,
                root_in_store: true,
                signatures_valid: true,
                trust_anchor: Some("Test Root CA".to_string()),
            },
        },
    );

    // Apple trusts
    platform_status.insert(
        TrustStore::Apple,
        PlatformTrustStatus {
            platform: TrustStore::Apple,
            trusted: true,
            trusted_root: Some("Test Root CA".to_string()),
            message: "Trusted".to_string(),
            details: ValidationDetails {
                chain_verified: true,
                root_in_store: true,
                signatures_valid: true,
                trust_anchor: Some("Test Root CA".to_string()),
            },
        },
    );

    // Others don't trust
    for platform in &[TrustStore::Android, TrustStore::Java, TrustStore::Windows] {
        platform_status.insert(
            *platform,
            PlatformTrustStatus {
                platform: *platform,
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
    }

    let result = cipherrun::certificates::trust_stores::TrustValidationResult {
        platform_status,
        overall_trusted: true,
        trusted_count: 2,
        total_platforms: 5,
    };

    // Test methods
    assert!(result.is_trusted_by(TrustStore::Mozilla));
    assert!(result.is_trusted_by(TrustStore::Apple));
    assert!(!result.is_trusted_by(TrustStore::Android));

    let trusted = result.trusted_platforms();
    assert_eq!(trusted.len(), 2);
    assert!(trusted.contains(&TrustStore::Mozilla));
    assert!(trusted.contains(&TrustStore::Apple));

    let untrusted = result.untrusted_platforms();
    assert_eq!(untrusted.len(), 3);

    let summary = result.summary();
    assert!(summary.contains("2/5"));
    println!("Summary: {}", summary);
}
