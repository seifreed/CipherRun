use cipherrun::certificates::parser::{CertificateChain, CertificateInfo};
use cipherrun::certificates::validator::{
    IssueSeverity, IssueType, ValidationIssue, ValidationResult,
};
use cipherrun::output::xml::generate_xml_report;
use cipherrun::protocols::{Protocol, ProtocolTestResult};
use cipherrun::rating::RatingResult;
use cipherrun::rating::grader::Grade;
use cipherrun::scanner::{CertificateAnalysisResult, RatingResults, ScanResults};
use cipherrun::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

fn build_test_results() -> ScanResults {
    let mut results = ScanResults {
        target: "example.com & <test>".to_string(),
        scan_time_ms: 1234,
        ..Default::default()
    };

    results.protocols = vec![ProtocolTestResult {
        protocol: Protocol::TLS13,
        supported: true,
        inconclusive: false,
        preferred: true,
        ciphers_count: 5,
        handshake_time_ms: Some(10),
        heartbeat_enabled: Some(true),
        session_resumption_caching: Some(true),
        session_resumption_tickets: Some(false),
        secure_renegotiation: Some(true),
    }];

    results.vulnerabilities = vec![VulnerabilityResult {
        vuln_type: VulnerabilityType::Heartbleed,
        vulnerable: false,
        inconclusive: false,
        details: "Safe & sound <ok>".to_string(),
        cve: Some("CVE-2014-0160".to_string()),
        cwe: None,
        severity: Severity::High,
    }];

    let cert = CertificateInfo {
        subject: "CN=example.com & Co".to_string(),
        issuer: "CN=Example CA <Root>".to_string(),
        serial_number: "00:11".to_string(),
        not_before: "2024-01-01 00:00:00 +00:00".to_string(),
        not_after: "2026-01-01 00:00:00 +00:00".to_string(),
        extended_validation: true,
        der_bytes: vec![1, 2, 3],
        ..Default::default()
    };

    let chain = CertificateChain {
        certificates: vec![cert],
        chain_length: 1,
        chain_size_bytes: 3,
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
        trusted_ca: Some("Example CA".to_string()),
        platform_trust: None,
    };

    results.certificate_chain = Some(CertificateAnalysisResult {
        chain,
        validation,
        revocation: None,
    });

    results.rating = Some(RatingResults {
        ssl_rating: Some(RatingResult {
            grade: Grade::A,
            score: 95,
            certificate_score: 90,
            protocol_score: 95,
            key_exchange_score: 95,
            cipher_strength_score: 95,
            warnings: vec![],
        }),
    });

    results
}

#[test]
fn test_generate_xml_report_basic() {
    let results = build_test_results();
    let xml = generate_xml_report(&results).expect("xml report");

    assert!(xml.contains("<document title=\"CipherRun Scan Results\">"));
    assert!(xml.contains("<target>example.com &amp; &lt;test&gt;</target>"));
    assert!(xml.contains("<scantime_ms>1234</scantime_ms>"));
    assert!(xml.contains("<name>TLS 1.3</name>"));
    assert!(xml.contains("<heartbeat_enabled>true</heartbeat_enabled>"));
    assert!(xml.contains("<vulnerable>false</vulnerable>"));
    assert!(xml.contains("<cve>CVE-2014-0160</cve>"));
    assert!(xml.contains("Safe &amp; sound &lt;ok&gt;"));
    assert!(xml.contains("<subject>CN=example.com &amp; Co</subject>"));
    assert!(xml.contains("<issuer>CN=Example CA &lt;Root&gt;</issuer>"));
    assert!(xml.contains("<extended_validation>true</extended_validation>"));
    assert!(xml.contains("<rating>"));
    assert!(xml.contains("<grade>A</grade>"));
}
