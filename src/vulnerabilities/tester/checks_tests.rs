use crate::ciphers::CipherSuite;
use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use crate::protocols::Protocol;
use crate::utils::network::Target;
use crate::vulnerabilities::{Severity, VulnerabilityType};
use std::net::TcpListener;
use std::sync::Once;

/// Install the rustls process-level crypto provider once for tests that drive
/// rustls-based checks (e.g. the 0-RTT early-data probe).
fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

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
    install_crypto_provider();
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

// --- rc4_probe_verdict ---

#[test]
fn rc4_probe_verdict_supported_is_vulnerable() {
    let supported = vec!["RC4-SHA".to_string()];
    let result = super::super::cipher_checks::rc4_probe_verdict(&supported, false);
    assert!(result.vulnerable);
    assert!(!result.inconclusive);
    assert_eq!(result.vuln_type, VulnerabilityType::RC4);
    assert_eq!(result.severity, Severity::Medium);
    assert!(result.details.contains("RC4-SHA"));
}

#[test]
fn rc4_probe_verdict_none_supported_is_not_vulnerable() {
    let result = super::super::cipher_checks::rc4_probe_verdict(&[], false);
    assert!(!result.vulnerable);
    assert!(!result.inconclusive);
    assert_eq!(result.severity, Severity::Info);
}

#[test]
fn rc4_probe_verdict_inconclusive_when_unclassified() {
    let result = super::super::cipher_checks::rc4_probe_verdict(&[], true);
    assert!(!result.vulnerable);
    assert!(result.inconclusive);
}

#[test]
fn rc4_probe_verdict_supported_overrides_inconclusive() {
    let supported = vec!["ECDHE-RSA-RC4-SHA".to_string()];
    let result = super::super::cipher_checks::rc4_probe_verdict(&supported, true);
    assert!(result.vulnerable);
    assert!(!result.inconclusive);
}

// --- null_probe_verdict ---

#[test]
fn null_probe_verdict_supported_is_vulnerable() {
    let supported = vec!["NULL-SHA".to_string()];
    let result = super::super::cipher_checks::null_probe_verdict(&supported, false);
    assert!(result.vulnerable);
    assert!(!result.inconclusive);
    assert_eq!(result.vuln_type, VulnerabilityType::NullCipher);
    assert_eq!(result.severity, Severity::Critical);
}

#[test]
fn null_probe_verdict_none_supported_is_not_vulnerable() {
    let result = super::super::cipher_checks::null_probe_verdict(&[], false);
    assert!(!result.vulnerable);
    assert!(!result.inconclusive);
}

#[test]
fn null_probe_verdict_inconclusive_when_unclassified() {
    let result = super::super::cipher_checks::null_probe_verdict(&[], true);
    assert!(!result.vulnerable);
    assert!(result.inconclusive);
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
