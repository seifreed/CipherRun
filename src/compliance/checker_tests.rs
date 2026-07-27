use super::*;
use crate::application::ScanAssessment;
use crate::certificates::parser::{CertificateChain, CertificateInfo};
use crate::certificates::revocation::{RevocationMethod, RevocationResult, RevocationStatus};
use crate::certificates::validator::ValidationResult;
use crate::ciphers::CipherSuite;
use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use crate::compliance::Rule;
use crate::compliance::test_support::base_rule;
use crate::protocols::Protocol;
use crate::protocols::test_support::supported_protocol_result as protocol_result;
use crate::scanner::CertificateAnalysisResult;
use crate::vulnerabilities::{Severity as VulnSeverity, VulnerabilityResult, VulnerabilityType};
use std::collections::HashMap;

fn create_certificate_assessment(not_after: String, not_expired: bool) -> ScanAssessment {
    create_certificate_assessment_with_revocation(not_after, not_expired, None)
}

fn create_certificate_assessment_with_revocation(
    not_after: String,
    not_expired: bool,
    revocation: Option<RevocationResult>,
) -> ScanAssessment {
    let cert = CertificateInfo {
        subject: "CN=example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial_number: "123456".to_string(),
        not_before: "2024-01-01 00:00:00 +0000".to_string(),
        not_after,
        expiry_countdown: None,
        signature_algorithm: "SHA256-RSA".to_string(),
        public_key_algorithm: "RSA".to_string(),
        public_key_size: Some(2048),
        rsa_exponent: None,
        san: vec!["example.com".to_string()],
        is_ca: false,
        key_usage: vec![],
        extended_key_usage: vec![],
        extended_validation: false,
        ev_oids: vec![],
        pin_sha256: None,
        fingerprint_sha256: None,
        debian_weak_key: None,
        aia_url: None,
        certificate_transparency: Some("Yes (certificate)".to_string()),
        der_bytes: vec![],
    };

    ScanAssessment {
        certificate_chain: Some(CertificateAnalysisResult {
            chain: CertificateChain {
                certificates: vec![cert],
                chain_length: 1,
                chain_size_bytes: 1000,
            },
            validation: ValidationResult {
                valid: not_expired,
                issues: Vec::new(),
                trust_chain_valid: true,
                hostname_match: true,
                not_expired,
                signature_valid: true,
                trusted_ca: None,
                platform_trust: None,
            },
            revocation,
        }),
        ..Default::default()
    }
}

fn leaf_certificate_mut(results: &mut ScanAssessment) -> &mut CertificateInfo {
    &mut results
        .certificate_chain
        .as_mut()
        .unwrap()
        .chain
        .certificates[0]
}

fn protocol_assessment(protocols: &[Protocol]) -> ScanAssessment {
    ScanAssessment {
        protocols: protocols.iter().cloned().map(protocol_result).collect(),
        ..Default::default()
    }
}

fn cipher_assessment(protocol: Protocol, cipher: CipherSuite) -> ScanAssessment {
    let mut ciphers = HashMap::new();
    ciphers.insert(
        protocol,
        ProtocolCipherSummary {
            protocol,
            supported_ciphers: vec![cipher],
            server_ordered: false,
            server_preference: vec![],
            preferred_cipher: None,
            counts: CipherCounts::default(),
            avg_handshake_time_ms: None,
        },
    );
    ScanAssessment {
        ciphers,
        ..Default::default()
    }
}

fn tls13_cipher(
    hexcode: &str,
    name: &str,
    protocol: &str,
    encryption: &str,
    mac: &str,
) -> CipherSuite {
    CipherSuite {
        hexcode: hexcode.to_string(),
        openssl_name: name.to_string(),
        iana_name: name.to_string(),
        protocol: protocol.to_string(),
        key_exchange: "".to_string(),
        authentication: "any".to_string(),
        encryption: encryption.to_string(),
        mac: mac.to_string(),
        bits: 128,
        export: false,
    }
}

#[test]
fn test_check_protocols_denied() {
    let rule = Rule {
        denied: vec!["SSLv2".to_string(), "SSLv3".to_string()],
        ..base_rule("ProtocolVersion")
    };

    let results = protocol_assessment(&[Protocol::SSLv2, Protocol::TLS12]);

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Prohibited Protocol");
}

#[test]
fn test_check_protocols_allowed() {
    let rule = Rule {
        allowed: vec!["TLS 1.2".to_string(), "TLS 1.3".to_string()],
        ..base_rule("ProtocolVersion")
    };

    let results = protocol_assessment(&[Protocol::TLS10, Protocol::TLS12]);

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Non-Compliant Protocol");
}

#[test]
fn test_check_protocols_allowed_names_are_normalized() {
    let rule = Rule {
        allowed: vec![" tls 1.2 ".to_string()],
        ..base_rule("ProtocolVersion")
    };

    let results = protocol_assessment(&[Protocol::TLS12]);

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert!(violations.is_empty());
}

#[test]
fn test_check_protocols_denied_names_are_normalized() {
    let rule = Rule {
        denied: vec!["sslv3".to_string()],
        ..base_rule("ProtocolVersion")
    };

    let results = protocol_assessment(&[Protocol::SSLv3]);

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Prohibited Protocol");
}

#[test]
fn test_check_key_size_flags_ec_public_key_algorithm() {
    let rule = Rule {
        min_ecc_bits: Some(256),
        ..base_rule("CertificateKeySize")
    };
    let mut results = create_certificate_assessment("2027-01-01 00:00:00 +0000".to_string(), true);
    let cert = leaf_certificate_mut(&mut results);
    cert.public_key_algorithm = "id-ecPublicKey".to_string();
    cert.public_key_size = Some(224);

    let violations =
        ComplianceChecker::check_key_size(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Insufficient Key Size");
    assert!(violations[0].description.contains("ECC key size"));
}

#[test]
fn test_check_forward_secrecy_treats_tls13_cipher_metadata_case_insensitively() {
    let rule = Rule {
        required: Some(true),
        ..base_rule("ForwardSecrecy")
    };

    let results = cipher_assessment(
        Protocol::TLS13,
        tls13_cipher(
            "0x1301",
            "tls_aes_128_gcm_sha256",
            "tlsv1.3",
            "aesgcm",
            "aead",
        ),
    );

    let violations = ComplianceChecker::check_forward_secrecy(&rule, &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_forward_secrecy_uses_protocol_bucket_for_tls13_ciphers() {
    let rule = Rule {
        required: Some(true),
        ..base_rule("ForwardSecrecy")
    };

    let results = cipher_assessment(
        Protocol::TLS13,
        tls13_cipher("0x00c6", "TLS_SM4_GCM_SM3", "TLS-1-3", "SM4-GCM", "AEAD"),
    );

    let violations = ComplianceChecker::check_forward_secrecy(&rule, &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_ciphers_exact_lists_are_case_insensitive() {
    let results = cipher_assessment(
        Protocol::TLS13,
        tls13_cipher(
            "0x1301",
            "TLS_AES_128_GCM_SHA256",
            "TLSv1.3",
            "aesgcm",
            "aead",
        ),
    );

    let allowed_rule = Rule {
        allowed: vec!["tls_aes_128_gcm_sha256".to_string()],
        ..base_rule("CipherSuite")
    };
    let violations = ComplianceChecker::check_ciphers(&allowed_rule, &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");

    let denied_rule = Rule {
        denied: vec!["tls_aes_128_gcm_sha256".to_string()],
        ..base_rule("CipherSuite")
    };
    let violations = ComplianceChecker::check_ciphers(&denied_rule, &results)
        .expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Prohibited Cipher Suite");
}

fn preferred_rule() -> Rule {
    Rule {
        preferred_patterns: vec![".*_GCM.*".to_string(), ".*_CHACHA20_POLY1305.*".to_string()],
        ..base_rule("CipherSuite")
    }
}

fn assessment_with_single_cipher(iana: &str, openssl: &str) -> ScanAssessment {
    cipher_assessment(
        Protocol::TLS12,
        CipherSuite {
            hexcode: "0x1301".to_string(),
            openssl_name: openssl.to_string(),
            iana_name: iana.to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "aes".to_string(),
            mac: "sha".to_string(),
            bits: 128,
            export: false,
        },
    )
}

#[test]
fn test_check_ciphers_preferred_pattern_matched_yields_no_violation() {
    let results = assessment_with_single_cipher(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
    );
    let violations = ComplianceChecker::check_ciphers(&preferred_rule(), &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_ciphers_preferred_pattern_unmatched_yields_medium_warning() {
    // CBC-only cipher: allowed but not preferred (no GCM/ChaCha).
    let results =
        assessment_with_single_cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA");
    let violations = ComplianceChecker::check_ciphers(&preferred_rule(), &results)
        .expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(
        violations[0].violation_type,
        "Preferred Cipher Suites Not Used"
    );
    assert_eq!(violations[0].severity, Severity::Medium);
}

#[test]
fn test_check_signature_denied_matches_hyphenated_alias() {
    let rule = Rule {
        denied: vec!["SHA1".to_string()],
        ..base_rule("SignatureAlgorithm")
    };
    let mut results = create_certificate_assessment("2027-01-01 00:00:00 +0000".to_string(), true);
    leaf_certificate_mut(&mut results).signature_algorithm = "SHA-1-RSA".to_string();

    let violations =
        ComplianceChecker::check_signature(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(
        violations[0].violation_type,
        "Prohibited Signature Algorithm"
    );
}

#[test]
fn test_check_signature_allowed_matches_separator_alias() {
    let rule = Rule {
        allowed: vec!["SHA1-RSA".to_string()],
        ..base_rule("SignatureAlgorithm")
    };
    let mut results = create_certificate_assessment("2027-01-01 00:00:00 +0000".to_string(), true);
    leaf_certificate_mut(&mut results).signature_algorithm = "SHA-1-RSA".to_string();

    let violations =
        ComplianceChecker::check_signature(&rule, &results).expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_signature_denied_rejects_partial_match() {
    let rule = Rule {
        denied: vec!["HA1".to_string()],
        ..base_rule("SignatureAlgorithm")
    };
    let mut results = create_certificate_assessment("2027-01-01 00:00:00 +0000".to_string(), true);
    leaf_certificate_mut(&mut results).signature_algorithm = "SHA-1-RSA".to_string();

    let violations =
        ComplianceChecker::check_signature(&rule, &results).expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_cert_validation_requires_revocation_check() {
    let rule = Rule {
        require_revocation_check: Some(true),
        ..base_rule("CertificateValidation")
    };

    let results = create_certificate_assessment_with_revocation(
        "2027-01-01 00:00:00 +0000".to_string(),
        true,
        Some(RevocationResult {
            status: RevocationStatus::Revoked,
            method: RevocationMethod::OCSP,
            details: "test revocation result".to_string(),
            ocsp_stapling: false,
            ocsp_stapling_details: None,
            must_staple: false,
        }),
    );

    let violations = ComplianceChecker::check_cert_validation(&rule, &results)
        .expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Revoked Certificate");
}

#[test]
fn test_check_cert_expiration_does_not_warn_for_recently_expired_certificates() {
    let rule = Rule {
        max_days_until_expiration: Some(30),
        ..base_rule("CertificateExpiration")
    };
    let not_after = (Utc::now() - chrono::Duration::hours(1))
        .format("%Y-%m-%d %H:%M:%S %z")
        .to_string();
    let results = create_certificate_assessment(not_after, false);

    let violations = ComplianceChecker::check_cert_expiration(&rule, &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_vulnerabilities_maps_severity_and_evidence() {
    let rule = base_rule("Vulnerability");

    let results = ScanAssessment {
        vulnerabilities: vec![
            VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "bad".to_string(),
                cve: None,
                cwe: None,
                severity: VulnSeverity::High,
            },
            VulnerabilityResult {
                vuln_type: VulnerabilityType::BEAST,
                vulnerable: false,
                inconclusive: false,
                details: "ok".to_string(),
                cve: Some("CVE-2011-3389".to_string()),
                cwe: None,
                severity: VulnSeverity::Medium,
            },
        ],
        ..Default::default()
    };

    let violations = ComplianceChecker::check_vulnerabilities(&rule, &results)
        .expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert!(violations[0].violation_type.contains("Heartbleed"));
    assert_eq!(violations[0].severity, Severity::High);
}

#[test]
fn test_check_vulnerabilities_ignores_inconclusive_findings() {
    // An inconclusive (unconfirmed) finding must not produce a compliance
    // violation: it would hard-fail compliance on evidence the scanner could
    // not confirm, contradicting its "Inconclusive" status in the scan report.
    let rule = base_rule("Vulnerability");

    let results = ScanAssessment {
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::ROBOT,
            vulnerable: true,
            inconclusive: true,
            details: "Timing signal below noise floor — unconfirmed".to_string(),
            cve: None,
            cwe: None,
            severity: VulnSeverity::Critical,
        }],
        ..Default::default()
    };

    let violations = ComplianceChecker::check_vulnerabilities(&rule, &results)
        .expect("test assertion should succeed");
    assert!(
        violations.is_empty(),
        "inconclusive findings must not create compliance violations"
    );
}
