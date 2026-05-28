use crate::ciphers::CipherSuite;
use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use crate::protocols::Protocol;
use crate::utils::network::Target;
use crate::vulnerabilities::{Severity, VulnerabilityType};
use std::net::TcpListener;

fn make_cipher(encryption: &str, bits: u16, export: bool) -> CipherSuite {
    CipherSuite {
        hexcode: "002F".to_string(),
        openssl_name: format!("TEST-{}", encryption),
        iana_name: format!("TLS_TEST_{}", encryption),
        protocol: "TLSv1.2".to_string(),
        key_exchange: "RSA".to_string(),
        authentication: "RSA".to_string(),
        encryption: encryption.to_string(),
        mac: "SHA256".to_string(),
        bits,
        export,
    }
}

fn empty_summary(protocol: Protocol) -> ProtocolCipherSummary {
    ProtocolCipherSummary {
        protocol,
        supported_ciphers: Vec::new(),
        server_ordered: false,
        server_preference: Vec::new(),
        preferred_cipher: None,
        counts: CipherCounts::default(),
        avg_handshake_time_ms: None,
    }
}

fn summary_with_ciphers(
    protocol: Protocol,
    ciphers: Vec<CipherSuite>,
    counts: CipherCounts,
) -> ProtocolCipherSummary {
    ProtocolCipherSummary {
        protocol,
        supported_ciphers: ciphers,
        server_ordered: false,
        server_preference: Vec::new(),
        preferred_cipher: None,
        counts,
        avg_handshake_time_ms: None,
    }
}

// --- test_drown ---

#[tokio::test]
async fn test_drown_inactive_target_is_inconclusive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let scanner = super::VulnerabilityScanner::new(target);
    let result = scanner.test_drown().await.unwrap();
    assert!(!result.vulnerable);
    assert!(
        result.inconclusive,
        "inactive target must not be reported as a clean DROWN pass: {}",
        result.details
    );
    assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
}

// --- test_poodle_ssl ---

#[tokio::test]
async fn test_poodle_ssl_inactive_target_is_inconclusive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let scanner = super::VulnerabilityScanner::new(target);
    let result = scanner.test_poodle_ssl().await.unwrap();
    assert!(!result.vulnerable);
    assert!(
        result.inconclusive,
        "inactive target must not be reported as a clean POODLE pass: {}",
        result.details
    );
    assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
}

// --- test_renegotiation ---

#[tokio::test]
async fn test_renegotiation_inactive_target_is_inconclusive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let scanner = super::VulnerabilityScanner::new(target);
    let result = scanner.test_renegotiation().await.unwrap();
    assert!(!result.vulnerable);
    assert!(
        result.inconclusive,
        "inactive target must not be reported as a clean renegotiation pass: {}",
        result.details
    );
    assert!(result.details.to_ascii_lowercase().contains("unclear"));
}

// --- test_padding_oracle_2016 ---

#[tokio::test]
async fn test_padding_oracle_2016_inactive_target_is_inconclusive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let scanner = super::VulnerabilityScanner::new(target);
    let result = scanner.test_padding_oracle_2016().await.unwrap();
    assert!(!result.vulnerable);
    assert!(
        result.inconclusive,
        "inactive target must not be reported as a clean padding-oracle pass: {}",
        result.details
    );
    assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
}

// --- test_early_data ---

#[tokio::test]
async fn test_early_data_inactive_target_is_inconclusive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let scanner = super::VulnerabilityScanner::new(target);
    let result = scanner.test_early_data().await.unwrap();
    assert!(!result.vulnerable);
    assert!(
        result.inconclusive,
        "inactive target must not be reported as a clean Early Data pass: {}",
        result.details
    );
    assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
}

// --- test_lucky13 ---

#[tokio::test]
async fn test_lucky13_inactive_target_is_inconclusive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let scanner = super::VulnerabilityScanner::new(target);
    let result = scanner.test_lucky13().await.unwrap();
    assert!(!result.vulnerable);
    assert!(
        result.inconclusive,
        "inactive target must not be reported as a clean Lucky13 pass: {}",
        result.details
    );
    assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
}

// --- evaluate_rc4 ---

#[test]
fn evaluate_rc4_empty_summaries() {
    let result = super::super::cipher_checks::evaluate_rc4(std::iter::empty());
    assert!(!result.vulnerable);
    assert!(result.inconclusive);
    assert_eq!(result.vuln_type, VulnerabilityType::RC4);
    assert_eq!(result.severity, Severity::Info);
}

#[test]
fn evaluate_rc4_no_rc4_ciphers() {
    let ciphers = vec![make_cipher("AES128-GCM", 128, false)];
    let summary = summary_with_ciphers(
        Protocol::TLS12,
        ciphers,
        CipherCounts {
            total: 1,
            high_strength: 1,
            aead: 1,
            ..Default::default()
        },
    );
    let result =
        super::super::cipher_checks::evaluate_rc4(std::iter::once((Protocol::TLS12, &summary)));
    assert!(!result.vulnerable);
    assert!(!result.inconclusive);
}

#[test]
fn evaluate_rc4_with_rc4_cipher() {
    let ciphers = vec![make_cipher("RC4-SHA", 128, false)];
    let summary = summary_with_ciphers(Protocol::TLS12, ciphers, CipherCounts::default());
    let result =
        super::super::cipher_checks::evaluate_rc4(std::iter::once((Protocol::TLS12, &summary)));
    assert!(result.vulnerable);
    assert_eq!(result.severity, Severity::Medium);
    assert!(result.details.contains("RC4"));
}

// --- evaluate_null ---

#[test]
fn evaluate_null_empty_summaries() {
    let result = super::super::cipher_checks::evaluate_null(std::iter::empty());
    assert!(!result.vulnerable);
    assert!(result.inconclusive);
    assert_eq!(result.vuln_type, VulnerabilityType::NullCipher);
}

#[test]
fn evaluate_null_with_null_ciphers() {
    let counts = CipherCounts {
        total: 1,
        null_ciphers: 1,
        ..Default::default()
    };
    let summary = summary_with_ciphers(Protocol::TLS12, Vec::new(), counts);
    let result =
        super::super::cipher_checks::evaluate_null(std::iter::once((Protocol::TLS12, &summary)));
    assert!(result.vulnerable);
    assert_eq!(result.severity, Severity::Critical);
}

#[test]
fn evaluate_null_without_null_ciphers() {
    let ciphers = vec![make_cipher("AES128-GCM", 128, false)];
    let summary = summary_with_ciphers(
        Protocol::TLS12,
        ciphers,
        CipherCounts {
            total: 1,
            high_strength: 1,
            aead: 1,
            ..Default::default()
        },
    );
    let result =
        super::super::cipher_checks::evaluate_null(std::iter::once((Protocol::TLS12, &summary)));
    assert!(!result.vulnerable);
    assert!(!result.inconclusive);
}

// --- evaluate_export ---

#[test]
fn evaluate_export_empty_summaries() {
    let result = super::super::cipher_checks::evaluate_export(std::iter::empty());
    assert!(!result.vulnerable);
    assert!(result.inconclusive);
    assert_eq!(result.vuln_type, VulnerabilityType::FREAK);
}

#[test]
fn evaluate_export_with_export_ciphers() {
    let counts = CipherCounts {
        total: 1,
        export_ciphers: 1,
        ..Default::default()
    };
    let summary = summary_with_ciphers(Protocol::TLS10, Vec::new(), counts);
    let result =
        super::super::cipher_checks::evaluate_export(std::iter::once((Protocol::TLS10, &summary)));
    assert!(result.vulnerable);
    assert_eq!(result.severity, Severity::High);
}

// --- evaluate_beast ---

#[test]
fn evaluate_beast_no_summary() {
    let result = super::super::cipher_checks::evaluate_beast(None, None);
    assert!(!result.vulnerable);
    assert_eq!(result.vuln_type, VulnerabilityType::BEAST);
    assert_eq!(result.severity, Severity::Info);
}

#[tokio::test]
async fn test_beast_inactive_target_is_inconclusive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = Target::with_ips(
        "localhost".to_string(),
        port,
        vec!["127.0.0.1".parse().unwrap()],
    )
    .unwrap();

    let scanner = super::VulnerabilityScanner::new(target);
    let result = scanner.test_beast().await.unwrap();
    assert!(!result.vulnerable);
    assert!(
        result.inconclusive,
        "inactive target must not be reported as a clean BEAST pass: {}",
        result.details
    );
    assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
}

#[test]
fn evaluate_beast_with_tls10_cbc_ciphers() {
    let ciphers = vec![make_cipher("AES128-CBC", 128, false)];
    let summary = summary_with_ciphers(Protocol::TLS10, ciphers, CipherCounts::default());
    let result = super::super::cipher_checks::evaluate_beast(Some(&summary), None);
    assert!(result.vulnerable);
    assert_eq!(result.severity, Severity::Medium);
    assert!(result.details.contains("TLS 1.0"));
    assert!(result.details.contains("CBC"));
}

#[test]
fn evaluate_beast_with_ssl3_cbc_ciphers() {
    let ciphers = vec![make_cipher("AES128-CBC", 128, false)];
    let summary = summary_with_ciphers(Protocol::SSLv3, ciphers, CipherCounts::default());
    let result = super::super::cipher_checks::evaluate_beast(None, Some(&summary));
    assert!(result.vulnerable);
    assert!(result.details.contains("SSL 3.0"));
}

#[test]
fn evaluate_beast_with_both_protocols() {
    let tls10_ciphers = vec![make_cipher("AES128-CBC", 128, false)];
    let tls10_summary =
        summary_with_ciphers(Protocol::TLS10, tls10_ciphers, CipherCounts::default());
    let ssl3_ciphers = vec![make_cipher("AES256-CBC", 256, false)];
    let ssl3_summary = summary_with_ciphers(Protocol::SSLv3, ssl3_ciphers, CipherCounts::default());
    let result =
        super::super::cipher_checks::evaluate_beast(Some(&tls10_summary), Some(&ssl3_summary));
    assert!(result.vulnerable);
    assert!(result.details.contains("TLS 1.0"));
    assert!(result.details.contains("SSL 3.0"));
}

#[test]
fn evaluate_beast_without_cbc_ciphers() {
    let ciphers = vec![make_cipher("AES128-GCM", 128, false)];
    let summary = summary_with_ciphers(Protocol::TLS10, ciphers, CipherCounts::default());
    let result = super::super::cipher_checks::evaluate_beast(Some(&summary), None);
    assert!(!result.vulnerable);
}

// --- evaluate across multiple protocols ---

#[test]
fn evaluate_rc4_across_multiple_protocols() {
    let s1 = empty_summary(Protocol::TLS10);
    let ciphers = vec![make_cipher("RC4-MD5", 128, false)];
    let s2 = summary_with_ciphers(Protocol::TLS12, ciphers, CipherCounts::default());
    let summaries = vec![(Protocol::TLS10, &s1), (Protocol::TLS12, &s2)];
    let result = super::super::cipher_checks::evaluate_rc4(summaries);
    assert!(result.vulnerable);
    assert!(result.details.contains("TLS 1.2"));
}

// --- VulnerabilityResult helper methods ---

#[test]
fn vulnerability_result_status_label_vulnerable() {
    let result = crate::vulnerabilities::VulnerabilityResult {
        vuln_type: VulnerabilityType::Heartbleed,
        vulnerable: true,
        inconclusive: false,
        details: String::new(),
        cve: None,
        cwe: None,
        severity: Severity::Critical,
    };
    assert_eq!(result.status_label(), "Vulnerable");
    assert_eq!(result.status_csv_value(), "vulnerable");
}

#[test]
fn vulnerability_result_status_label_not_vulnerable() {
    let result = crate::vulnerabilities::VulnerabilityResult {
        vuln_type: VulnerabilityType::Heartbleed,
        vulnerable: false,
        inconclusive: false,
        details: String::new(),
        cve: None,
        cwe: None,
        severity: Severity::Info,
    };
    assert_eq!(result.status_label(), "Not Vulnerable");
    assert_eq!(result.status_csv_value(), "not_vulnerable");
}

#[test]
fn vulnerability_result_status_label_inconclusive() {
    let result = crate::vulnerabilities::VulnerabilityResult {
        vuln_type: VulnerabilityType::ROBOT,
        vulnerable: false,
        inconclusive: true,
        details: String::new(),
        cve: None,
        cwe: None,
        severity: Severity::Info,
    };
    assert_eq!(result.status_label(), "Inconclusive");
    assert_eq!(result.status_csv_value(), "inconclusive");
}
