use super::*;
use crate::application::ScanAssessment;
use crate::certificates::parser::{CertificateChain, CertificateInfo};
use crate::certificates::validator::ValidationResult;
use crate::ciphers::CipherSuite;
use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use crate::compliance::Rule;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::scanner::CertificateAnalysisResult;
use crate::vulnerabilities::{Severity as VulnSeverity, VulnerabilityResult, VulnerabilityType};
use std::collections::HashMap;

fn create_certificate_assessment(not_after: String, not_expired: bool) -> ScanAssessment {
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
            revocation: None,
        }),
        ..Default::default()
    }
}

#[test]
fn test_check_protocols_denied() {
    let rule = Rule {
        rule_type: "ProtocolVersion".to_string(),
        allowed: vec![],
        denied: vec!["SSLv2".to_string(), "SSLv3".to_string()],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

    let results = ScanAssessment {
        protocols: vec![
            ProtocolTestResult {
                protocol: Protocol::SSLv2,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
        ],
        ..Default::default()
    };

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Prohibited Protocol");
}

#[test]
fn test_check_protocols_allowed() {
    let rule = Rule {
        rule_type: "ProtocolVersion".to_string(),
        allowed: vec!["TLS 1.2".to_string(), "TLS 1.3".to_string()],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

    let results = ScanAssessment {
        protocols: vec![
            ProtocolTestResult {
                protocol: Protocol::TLS10,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            },
        ],
        ..Default::default()
    };

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Non-Compliant Protocol");
}

#[test]
fn test_check_protocols_allowed_names_are_normalized() {
    let rule = Rule {
        rule_type: "ProtocolVersion".to_string(),
        allowed: vec![" tls 1.2 ".to_string()],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

    let results = ScanAssessment {
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            inconclusive: false,
            preferred: false,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert!(violations.is_empty());
}

#[test]
fn test_check_protocols_denied_names_are_normalized() {
    let rule = Rule {
        rule_type: "ProtocolVersion".to_string(),
        allowed: vec![],
        denied: vec!["sslv3".to_string()],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

    let results = ScanAssessment {
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::SSLv3,
            supported: true,
            inconclusive: false,
            preferred: false,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };

    let violations =
        ComplianceChecker::check_protocols(&rule, &results).expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Prohibited Protocol");
}

#[test]
fn test_check_forward_secrecy_treats_tls13_cipher_metadata_case_insensitively() {
    let rule = Rule {
        rule_type: "ForwardSecrecy".to_string(),
        allowed: vec![],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: Some(true),
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

    let cipher = CipherSuite {
        hexcode: "0x1301".to_string(),
        openssl_name: "tls_aes_128_gcm_sha256".to_string(),
        iana_name: "tls_aes_128_gcm_sha256".to_string(),
        protocol: "tlsv1.3".to_string(),
        key_exchange: "".to_string(),
        authentication: "any".to_string(),
        encryption: "aesgcm".to_string(),
        mac: "aead".to_string(),
        bits: 128,
        export: false,
    };
    let mut ciphers = HashMap::new();
    ciphers.insert(
        Protocol::TLS13,
        ProtocolCipherSummary {
            protocol: Protocol::TLS13,
            supported_ciphers: vec![cipher],
            server_ordered: false,
            server_preference: vec![],
            preferred_cipher: None,
            counts: CipherCounts::default(),
            avg_handshake_time_ms: None,
        },
    );
    let results = ScanAssessment {
        ciphers,
        ..Default::default()
    };

    let violations = ComplianceChecker::check_forward_secrecy(&rule, &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_forward_secrecy_uses_protocol_bucket_for_tls13_ciphers() {
    let rule = Rule {
        rule_type: "ForwardSecrecy".to_string(),
        allowed: vec![],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: Some(true),
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

    let cipher = CipherSuite {
        hexcode: "0x00c6".to_string(),
        openssl_name: "TLS_SM4_GCM_SM3".to_string(),
        iana_name: "TLS_SM4_GCM_SM3".to_string(),
        protocol: "TLS-1-3".to_string(),
        key_exchange: "".to_string(),
        authentication: "any".to_string(),
        encryption: "SM4-GCM".to_string(),
        mac: "AEAD".to_string(),
        bits: 128,
        export: false,
    };
    let mut ciphers = HashMap::new();
    ciphers.insert(
        Protocol::TLS13,
        ProtocolCipherSummary {
            protocol: Protocol::TLS13,
            supported_ciphers: vec![cipher],
            server_ordered: false,
            server_preference: vec![],
            preferred_cipher: None,
            counts: CipherCounts::default(),
            avg_handshake_time_ms: None,
        },
    );
    let results = ScanAssessment {
        ciphers,
        ..Default::default()
    };

    let violations = ComplianceChecker::check_forward_secrecy(&rule, &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_ciphers_exact_lists_are_case_insensitive() {
    let cipher = CipherSuite {
        hexcode: "0x1301".to_string(),
        openssl_name: "TLS_AES_128_GCM_SHA256".to_string(),
        iana_name: "TLS_AES_128_GCM_SHA256".to_string(),
        protocol: "TLSv1.3".to_string(),
        key_exchange: "".to_string(),
        authentication: "any".to_string(),
        encryption: "aesgcm".to_string(),
        mac: "aead".to_string(),
        bits: 128,
        export: false,
    };
    let mut ciphers = HashMap::new();
    ciphers.insert(
        Protocol::TLS13,
        ProtocolCipherSummary {
            protocol: Protocol::TLS13,
            supported_ciphers: vec![cipher],
            server_ordered: false,
            server_preference: vec![],
            preferred_cipher: None,
            counts: CipherCounts::default(),
            avg_handshake_time_ms: None,
        },
    );
    let results = ScanAssessment {
        ciphers,
        ..Default::default()
    };

    let allowed_rule = Rule {
        rule_type: "CipherSuite".to_string(),
        allowed: vec!["tls_aes_128_gcm_sha256".to_string()],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };
    let violations = ComplianceChecker::check_ciphers(&allowed_rule, &results)
        .expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");

    let denied_rule = Rule {
        rule_type: "CipherSuite".to_string(),
        allowed: vec![],
        denied: vec!["tls_aes_128_gcm_sha256".to_string()],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };
    let violations = ComplianceChecker::check_ciphers(&denied_rule, &results)
        .expect("test assertion should succeed");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].violation_type, "Prohibited Cipher Suite");
}

#[test]
fn test_check_signature_denied_matches_hyphenated_alias() {
    let rule = Rule {
        rule_type: "SignatureAlgorithm".to_string(),
        allowed: vec![],
        denied: vec!["SHA1".to_string()],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };
    let mut results = create_certificate_assessment("2027-01-01 00:00:00 +0000".to_string(), true);
    results
        .certificate_chain
        .as_mut()
        .unwrap()
        .chain
        .certificates[0]
        .signature_algorithm = "SHA-1-RSA".to_string();

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
        rule_type: "SignatureAlgorithm".to_string(),
        allowed: vec!["SHA1-RSA".to_string()],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };
    let mut results = create_certificate_assessment("2027-01-01 00:00:00 +0000".to_string(), true);
    results
        .certificate_chain
        .as_mut()
        .unwrap()
        .chain
        .certificates[0]
        .signature_algorithm = "SHA-1-RSA".to_string();

    let violations =
        ComplianceChecker::check_signature(&rule, &results).expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_signature_denied_rejects_partial_match() {
    let rule = Rule {
        rule_type: "SignatureAlgorithm".to_string(),
        allowed: vec![],
        denied: vec!["HA1".to_string()],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };
    let mut results = create_certificate_assessment("2027-01-01 00:00:00 +0000".to_string(), true);
    results
        .certificate_chain
        .as_mut()
        .unwrap()
        .chain
        .certificates[0]
        .signature_algorithm = "SHA-1-RSA".to_string();

    let violations =
        ComplianceChecker::check_signature(&rule, &results).expect("test assertion should succeed");
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn test_check_cert_expiration_does_not_warn_for_recently_expired_certificates() {
    let rule = Rule {
        rule_type: "CertificateExpiration".to_string(),
        allowed: vec![],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: Some(30),
        custom_params: HashMap::new(),
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
    let rule = Rule {
        rule_type: "Vulnerability".to_string(),
        allowed: vec![],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

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
    let rule = Rule {
        rule_type: "Vulnerability".to_string(),
        allowed: vec![],
        denied: vec![],
        allowed_patterns: vec![],
        denied_patterns: vec![],
        preferred_patterns: vec![],
        min_rsa_bits: None,
        min_ecc_bits: None,
        required: None,
        require_valid_chain: None,
        require_unexpired: None,
        require_hostname_match: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    };

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
