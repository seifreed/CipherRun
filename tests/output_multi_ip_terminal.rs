use std::collections::HashMap;
use std::net::IpAddr;

use cipherrun::certificates::parser::{CertificateChain, CertificateInfo};
use cipherrun::certificates::validator::{
    IssueSeverity, IssueType, ValidationIssue, ValidationResult,
};
use cipherrun::ciphers::CipherSuite;
use cipherrun::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use cipherrun::protocols::{Protocol, ProtocolTestResult};
use cipherrun::rating::RatingResult;
use cipherrun::rating::grader::Grade;
use cipherrun::scanner::aggregation::AggregatedScanResult;
use cipherrun::scanner::inconsistency::{
    Inconsistency, InconsistencyDetails, InconsistencyType, SingleIpScanResult,
};
use cipherrun::scanner::multi_ip::MultiIpScanReport;
use cipherrun::scanner::{CertificateAnalysisResult, RatingResults, ScanResults};
use cipherrun::utils::network::Target;
use cipherrun::vulnerabilities::Severity;

fn build_cipher_summary(protocol: Protocol) -> ProtocolCipherSummary {
    let cipher = CipherSuite {
        hexcode: "1301".to_string(),
        openssl_name: "TLS_AES_128_GCM_SHA256".to_string(),
        iana_name: "TLS_AES_128_GCM_SHA256".to_string(),
        protocol: "TLSv1.3".to_string(),
        key_exchange: "ECDHE".to_string(),
        authentication: "AEAD".to_string(),
        encryption: "AES_128_GCM".to_string(),
        mac: "AEAD".to_string(),
        bits: 128,
        export: false,
    };

    ProtocolCipherSummary {
        protocol,
        supported_ciphers: vec![cipher],
        server_ordered: true,
        server_preference: vec!["1301".to_string()],
        preferred_cipher: None,
        counts: CipherCounts {
            total: 1,
            null_ciphers: 0,
            export_ciphers: 0,
            low_strength: 0,
            medium_strength: 1,
            high_strength: 0,
            forward_secrecy: 1,
            aead: 1,
        },
        avg_handshake_time_ms: Some(10),
    }
}

fn build_scan_results() -> ScanResults {
    let mut results = ScanResults {
        target: "example.com:443".to_string(),
        scan_time_ms: 250,
        ..Default::default()
    };
    results.protocols = vec![ProtocolTestResult {
        protocol: Protocol::TLS13,
        supported: true,
        inconclusive: false,
        preferred: true,
        ciphers_count: 1,
        handshake_time_ms: Some(10),
        heartbeat_enabled: Some(false),
        session_resumption_caching: Some(true),
        session_resumption_tickets: Some(false),
        secure_renegotiation: Some(true),
    }];

    let mut ciphers = HashMap::new();
    ciphers.insert(Protocol::TLS13, build_cipher_summary(Protocol::TLS13));
    results.ciphers = ciphers;

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

    results.certificate_chain = Some(CertificateAnalysisResult {
        chain,
        validation,
        revocation: None,
    });

    results.rating = Some(RatingResults {
        ssl_rating: Some(RatingResult {
            grade: Grade::B,
            score: 85,
            certificate_score: 90,
            protocol_score: 80,
            key_exchange_score: 85,
            cipher_strength_score: 85,
            warnings: vec![],
        }),
    });

    results
}

#[test]
fn test_multi_ip_report_display() {
    colored::control::set_override(false);

    let ip1: IpAddr = "192.0.2.1".parse().unwrap();
    let ip2: IpAddr = "192.0.2.2".parse().unwrap();

    let target = Target::with_ips("example.com".to_string(), 443, vec![ip1, ip2]).unwrap();

    let success = SingleIpScanResult {
        ip: ip1,
        scan_result: build_scan_results(),
        scan_duration_ms: 120,
        error: None,
    };

    let failure = SingleIpScanResult {
        ip: ip2,
        scan_result: ScanResults::default(),
        scan_duration_ms: 80,
        error: Some("timeout".to_string()),
    };

    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(ip1, success);
    per_ip_results.insert(ip2, failure);

    let mut grades = HashMap::new();
    grades.insert(ip1, ("A".to_string(), 95));
    grades.insert(ip2, ("C".to_string(), 70));

    let mut fingerprints = HashMap::new();
    fingerprints.insert(ip1, "abc1234567890def".to_string());
    fingerprints.insert(ip2, "def1234567890abc".to_string());

    let mut cipher_diffs = HashMap::new();
    cipher_diffs.insert(ip1, vec!["TLS_AES_128_GCM_SHA256".to_string()]);
    cipher_diffs.insert(ip2, vec!["TLS_AES_256_GCM_SHA384".to_string()]);

    let mut alpn = HashMap::new();
    alpn.insert(ip1, vec!["h2".to_string(), "http/1.1".to_string()]);
    alpn.insert(ip2, vec!["http/1.1".to_string()]);

    let inconsistencies = vec![
        Inconsistency {
            inconsistency_type: InconsistencyType::ProtocolSupport,
            severity: Severity::High,
            description: "TLS 1.3 mismatch".to_string(),
            ips_affected: vec![ip1, ip2],
            details: InconsistencyDetails::Protocols {
                protocol: Protocol::TLS13,
                ips_with_support: vec![ip1],
                ips_without_support: vec![ip2],
            },
        },
        Inconsistency {
            inconsistency_type: InconsistencyType::Certificates,
            severity: Severity::Critical,
            description: "Certificate mismatch".to_string(),
            ips_affected: vec![ip1, ip2],
            details: InconsistencyDetails::Certificates { fingerprints },
        },
        Inconsistency {
            inconsistency_type: InconsistencyType::SecurityGrade,
            severity: Severity::Medium,
            description: "Grades differ".to_string(),
            ips_affected: vec![ip1, ip2],
            details: InconsistencyDetails::Grades { grades },
        },
        Inconsistency {
            inconsistency_type: InconsistencyType::CipherSuites,
            severity: Severity::Low,
            description: "Cipher mismatch".to_string(),
            ips_affected: vec![ip1, ip2],
            details: InconsistencyDetails::CipherSuites {
                differences: cipher_diffs,
            },
        },
        Inconsistency {
            inconsistency_type: InconsistencyType::SessionResumption,
            severity: Severity::Info,
            description: "Session resumption differs".to_string(),
            ips_affected: vec![ip1, ip2],
            details: InconsistencyDetails::SessionResumption {
                ips_with_caching: vec![ip1],
                ips_with_tickets: vec![ip2],
                ips_without: vec![],
            },
        },
        Inconsistency {
            inconsistency_type: InconsistencyType::Alpn,
            severity: Severity::Info,
            description: "ALPN differs".to_string(),
            ips_affected: vec![ip1, ip2],
            details: InconsistencyDetails::Alpn {
                protocols_by_ip: alpn,
            },
        },
    ];

    let aggregated = AggregatedScanResult {
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            inconclusive: false,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(false),
            secure_renegotiation: None,
        }],
        ciphers: HashMap::new(),
        grade: ("B".to_string(), 85),
        certificate_info: None,
        certificate_consistent: false,
        inconsistencies: inconsistencies.clone(),
        alpn_protocols: vec!["h2".to_string()],
        session_resumption_caching: Some(true),
        session_resumption_tickets: Some(false),
    };

    let report = MultiIpScanReport {
        target,
        per_ip_results,
        total_ips: 2,
        successful_scans: 1,
        failed_scans: 1,
        total_duration_ms: 500,
        inconsistencies,
        aggregated,
    };

    let output = format!("{}", report);
    assert!(output.contains("MULTI-IP SCAN REPORT"));
    assert!(output.contains("Target: example.com:443"));
    assert!(output.contains("IPs Scanned: 1/2 successful"));
    assert!(output.contains("FAILED"));
    assert!(output.contains("Inconsistencies Detected"));
    assert!(output.contains("Aggregated Results"));
    assert!(output.contains("Recommendations:"));
}

#[test]
fn test_multi_ip_report_display_is_deterministic() {
    colored::control::set_override(false);

    let build_report = |reverse: bool| {
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();

        let target = Target::with_ips("example.com".to_string(), 443, vec![ip1, ip2]).unwrap();

        let success = SingleIpScanResult {
            ip: ip1,
            scan_result: build_scan_results(),
            scan_duration_ms: 120,
            error: None,
        };

        let failure = SingleIpScanResult {
            ip: ip2,
            scan_result: ScanResults::default(),
            scan_duration_ms: 80,
            error: Some("timeout".to_string()),
        };

        let mut per_ip_results = HashMap::new();
        if reverse {
            per_ip_results.insert(ip2, failure.clone());
            per_ip_results.insert(ip1, success.clone());
        } else {
            per_ip_results.insert(ip1, success.clone());
            per_ip_results.insert(ip2, failure.clone());
        }

        let mut grades = HashMap::new();
        if reverse {
            grades.insert(ip2, ("C".to_string(), 70));
            grades.insert(ip1, ("A".to_string(), 95));
        } else {
            grades.insert(ip1, ("A".to_string(), 95));
            grades.insert(ip2, ("C".to_string(), 70));
        }

        let mut fingerprints = HashMap::new();
        if reverse {
            fingerprints.insert(ip2, "def1234567890abc".to_string());
            fingerprints.insert(ip1, "abc1234567890def".to_string());
        } else {
            fingerprints.insert(ip1, "abc1234567890def".to_string());
            fingerprints.insert(ip2, "def1234567890abc".to_string());
        }

        let mut cipher_diffs = HashMap::new();
        if reverse {
            cipher_diffs.insert(ip2, vec!["TLS_AES_256_GCM_SHA384".to_string()]);
            cipher_diffs.insert(ip1, vec!["TLS_AES_128_GCM_SHA256".to_string()]);
        } else {
            cipher_diffs.insert(ip1, vec!["TLS_AES_128_GCM_SHA256".to_string()]);
            cipher_diffs.insert(ip2, vec!["TLS_AES_256_GCM_SHA384".to_string()]);
        }

        let mut alpn = HashMap::new();
        if reverse {
            alpn.insert(ip2, vec!["http/1.1".to_string()]);
            alpn.insert(ip1, vec!["h2".to_string(), "http/1.1".to_string()]);
        } else {
            alpn.insert(ip1, vec!["h2".to_string(), "http/1.1".to_string()]);
            alpn.insert(ip2, vec!["http/1.1".to_string()]);
        }

        let inconsistencies = vec![
            Inconsistency {
                inconsistency_type: InconsistencyType::ProtocolSupport,
                severity: Severity::High,
                description: "TLS 1.3 mismatch".to_string(),
                ips_affected: vec![ip1, ip2],
                details: InconsistencyDetails::Protocols {
                    protocol: Protocol::TLS13,
                    ips_with_support: vec![ip1],
                    ips_without_support: vec![ip2],
                },
            },
            Inconsistency {
                inconsistency_type: InconsistencyType::Certificates,
                severity: Severity::Critical,
                description: "Certificate mismatch".to_string(),
                ips_affected: vec![ip1, ip2],
                details: InconsistencyDetails::Certificates { fingerprints },
            },
            Inconsistency {
                inconsistency_type: InconsistencyType::SecurityGrade,
                severity: Severity::Medium,
                description: "Grades differ".to_string(),
                ips_affected: vec![ip1, ip2],
                details: InconsistencyDetails::Grades { grades },
            },
            Inconsistency {
                inconsistency_type: InconsistencyType::CipherSuites,
                severity: Severity::Low,
                description: "Cipher mismatch".to_string(),
                ips_affected: vec![ip1, ip2],
                details: InconsistencyDetails::CipherSuites {
                    differences: cipher_diffs,
                },
            },
            Inconsistency {
                inconsistency_type: InconsistencyType::SessionResumption,
                severity: Severity::Info,
                description: "Session resumption differs".to_string(),
                ips_affected: vec![ip1, ip2],
                details: InconsistencyDetails::SessionResumption {
                    ips_with_caching: vec![ip1],
                    ips_with_tickets: vec![ip2],
                    ips_without: vec![],
                },
            },
            Inconsistency {
                inconsistency_type: InconsistencyType::Alpn,
                severity: Severity::Info,
                description: "ALPN differs".to_string(),
                ips_affected: vec![ip1, ip2],
                details: InconsistencyDetails::Alpn {
                    protocols_by_ip: alpn,
                },
            },
        ];

        let aggregated = AggregatedScanResult {
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                inconclusive: false,
                preferred: true,
                ciphers_count: 1,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: Some(true),
                session_resumption_tickets: Some(false),
                secure_renegotiation: None,
            }],
            ciphers: HashMap::new(),
            grade: ("B".to_string(), 85),
            certificate_info: None,
            certificate_consistent: false,
            inconsistencies: inconsistencies.clone(),
            alpn_protocols: vec!["h2".to_string()],
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(false),
        };

        MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 2,
            successful_scans: 1,
            failed_scans: 1,
            total_duration_ms: 500,
            inconsistencies,
            aggregated,
        }
    };

    let output_a = format!("{}", build_report(false));
    let output_b = format!("{}", build_report(true));

    assert_eq!(output_a, output_b);
}
