use std::collections::HashMap;

mod common;

use cipherrun::Args;
use cipherrun::certificates::parser::{CertificateChain, CertificateInfo};
use cipherrun::certificates::validator::{
    IssueSeverity, IssueType, ValidationIssue, ValidationResult,
};
use cipherrun::output::ScannerFormatter;
use cipherrun::protocols::{Protocol, ProtocolTestResult};
use cipherrun::rating::RatingResult;
use cipherrun::rating::grader::Grade;
use cipherrun::scanner::CertificateAnalysisResult;
use cipherrun::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

fn build_cert_result() -> CertificateAnalysisResult {
    let cert = CertificateInfo {
        subject: "CN=example.com".to_string(),
        issuer: "CN=Example CA".to_string(),
        serial_number: "01".to_string(),
        not_before: "2024-01-01 00:00:00 +00:00".to_string(),
        not_after: "2026-01-01 00:00:00 +00:00".to_string(),
        extended_validation: false,
        der_bytes: vec![1, 2],
        ..Default::default()
    };

    let chain = CertificateChain {
        certificates: vec![cert],
        chain_length: 1,
        chain_size_bytes: 2,
    };

    let validation = ValidationResult {
        valid: true,
        issues: vec![ValidationIssue {
            severity: IssueSeverity::Info,
            issue_type: IssueType::MissingExtension,
            description: "Missing SCT".to_string(),
        }],
        trust_chain_valid: true,
        hostname_match: true,
        not_expired: true,
        signature_valid: true,
        trusted_ca: None,
        platform_trust: None,
    };

    CertificateAnalysisResult {
        chain,
        validation,
        revocation: None,
    }
}

#[test]
fn test_scanner_formatter_display_helpers() {
    colored::control::set_override(false);

    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);

    let protocols = vec![
        common::output::supported_tls13_protocol_result(),
        ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: false,
            inconclusive: false,
            preferred: false,
            ciphers_count: 0,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        },
    ];

    let mut cipher_results = HashMap::new();
    cipher_results.insert(
        Protocol::TLS13,
        common::output::build_cipher_summary(Protocol::TLS13),
    );

    let cert_result = build_cert_result();

    let vulns = vec![VulnerabilityResult {
        vuln_type: VulnerabilityType::Heartbleed,
        vulnerable: false,
        inconclusive: false,
        details: "Not vulnerable".to_string(),
        cve: Some("CVE-2014-0160".to_string()),
        cwe: None,
        severity: Severity::High,
    }];

    let rating = RatingResult {
        grade: Grade::A,
        score: 95,
        certificate_score: 90,
        protocol_score: 95,
        key_exchange_score: 95,
        cipher_strength_score: 95,
        warnings: vec!["Test warning".to_string()],
    };

    formatter.display_protocol_results(&protocols);
    formatter.display_cipher_results(&cipher_results);
    formatter.display_certificate_results(&cert_result);
    formatter.display_vulnerability_results(&vulns);
    formatter.display_rating_results(&rating);
}
