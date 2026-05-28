use super::*;
use crate::certificates::parser::CertificateInfo;
use crate::certificates::validator::ValidationResult;
use crate::ciphers::CipherSuite;
use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use crate::rating::grader::Grade;
use crate::rating::scoring::RatingResult;
use crate::scanner::{
    AdvancedResults, CertificateAnalysisResult, ProtocolTestResult, RatingResults, ScanResults,
};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_inconsistency_type_display() {
    assert_eq!(
        format!("{}", InconsistencyType::ProtocolSupport),
        "Protocol Support"
    );
    assert_eq!(
        format!("{}", InconsistencyType::Certificates),
        "Certificates"
    );
}

#[test]
fn test_inconsistency_type_display_alpn() {
    assert_eq!(format!("{}", InconsistencyType::Alpn), "ALPN Support");
}

#[test]
fn test_single_ip_scan_result_success_flag_with_error() {
    let ip = "192.0.2.1".parse().expect("test assertion should succeed");
    let result = SingleIpScanResult {
        ip,
        scan_result: ScanResults::default(),
        scan_duration_ms: 10,
        error: None,
    };
    assert!(result.is_successful());

    let result = SingleIpScanResult {
        error: Some("fail".to_string()),
        ..result
    };
    assert!(!result.is_successful());
}

#[test]
fn test_detector_with_no_results() {
    let detector = InconsistencyDetector::new(HashMap::new());
    let inconsistencies = detector.detect_all();
    assert!(inconsistencies.is_empty());
}

#[test]
fn test_detector_with_single_result() {
    let mut results = HashMap::new();
    let ip = "192.168.1.1"
        .parse()
        .expect("test assertion should succeed");
    results.insert(
        ip,
        SingleIpScanResult {
            ip,
            scan_result: ScanResults::default(),
            scan_duration_ms: 1000,
            error: None,
        },
    );

    let detector = InconsistencyDetector::new(results);
    let inconsistencies = detector.detect_all();
    // Single IP should not have inconsistencies
    assert!(inconsistencies.is_empty());
}

fn make_cipher(name: &str) -> CipherSuite {
    CipherSuite {
        hexcode: "0001".to_string(),
        openssl_name: name.to_string(),
        iana_name: name.to_string(),
        protocol: "TLSv1.2".to_string(),
        key_exchange: "RSA".to_string(),
        authentication: "RSA".to_string(),
        encryption: "AES".to_string(),
        mac: "SHA256".to_string(),
        bits: 128,
        export: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_scan(
    protocol: Protocol,
    supported: bool,
    fingerprint: Option<&str>,
    cipher_name: &str,
    grade: Grade,
    caching: Option<bool>,
    tickets: Option<bool>,
    alpn_protocols: Option<Vec<String>>,
) -> ScanResults {
    let mut scan = ScanResults {
        target: "example.test:443".to_string(),
        ..Default::default()
    };

    scan.protocols.push(ProtocolTestResult {
        protocol,
        supported,
        inconclusive: false,
        preferred: false,
        ciphers_count: 1,
        handshake_time_ms: None,
        heartbeat_enabled: None,
        session_resumption_caching: caching,
        session_resumption_tickets: tickets,
        secure_renegotiation: None,
    });

    let summary = ProtocolCipherSummary {
        protocol,
        supported_ciphers: vec![make_cipher(cipher_name)],
        server_ordered: false,
        server_preference: Vec::new(),
        preferred_cipher: None,
        counts: CipherCounts::default(),
        avg_handshake_time_ms: None,
    };
    scan.ciphers.insert(protocol, summary);

    if let Some(fp) = fingerprint {
        let cert = CertificateInfo {
            fingerprint_sha256: Some(fp.to_string()),
            ..Default::default()
        };
        let chain = crate::certificates::parser::CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 0,
        };
        let validation = ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        };
        scan.certificate_chain = Some(CertificateAnalysisResult {
            chain,
            validation,
            revocation: None,
        });
    }

    scan.rating = Some(RatingResults {
        ssl_rating: Some(RatingResult {
            grade,
            score: match grade {
                Grade::A => 90,
                Grade::B => 80,
                _ => 70,
            },
            certificate_score: 90,
            protocol_score: 90,
            key_exchange_score: 90,
            cipher_strength_score: 90,
            warnings: Vec::new(),
        }),
    });

    if let Some(protocols) = alpn_protocols {
        scan.advanced = Some(AdvancedResults {
            alpn_result: Some(crate::protocols::alpn::AlpnReport {
                alpn_enabled: true,
                alpn_result: crate::protocols::alpn::AlpnResult {
                    supported_protocols: protocols,
                    http2_supported: true,
                    http3_supported: false,
                    negotiated_protocol: None,
                    details: Vec::new(),
                    inconclusive: false,
                },
                spdy_supported: false,
                recommendations: Vec::new(),
                inconclusive: false,
            }),
            ..Default::default()
        });
    }

    scan
}

#[test]
fn test_detects_multiple_inconsistencies() {
    let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

    let scan1 = make_scan(
        Protocol::TLS13,
        true,
        Some("fp1"),
        "CIPHER1",
        Grade::A,
        Some(true),
        Some(true),
        Some(vec!["h2".to_string()]),
    );
    let scan2 = make_scan(
        Protocol::TLS12,
        true,
        Some("fp2"),
        "CIPHER2",
        Grade::B,
        None,
        None,
        None,
    );

    let mut results = HashMap::new();
    results.insert(
        ip1,
        SingleIpScanResult {
            ip: ip1,
            scan_result: scan1,
            scan_duration_ms: 100,
            error: None,
        },
    );
    results.insert(
        ip2,
        SingleIpScanResult {
            ip: ip2,
            scan_result: scan2,
            scan_duration_ms: 120,
            error: None,
        },
    );

    let detector = InconsistencyDetector::new(results);
    let inconsistencies = detector.detect_all();

    let kinds: Vec<InconsistencyType> = inconsistencies
        .iter()
        .map(|i| i.inconsistency_type.clone())
        .collect();

    assert!(kinds.contains(&InconsistencyType::ProtocolSupport));
    assert!(kinds.contains(&InconsistencyType::Certificates));
    assert!(kinds.contains(&InconsistencyType::CipherSuites));
    assert!(kinds.contains(&InconsistencyType::SecurityGrade));
    assert!(kinds.contains(&InconsistencyType::SessionResumption));
    assert!(kinds.contains(&InconsistencyType::Alpn));
}

#[test]
fn test_protocol_inconsistency_denominator_excludes_failed_scans() {
    let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();
    let ip3: IpAddr = Ipv4Addr::new(127, 0, 0, 3).into();

    let scan1 = make_scan(
        Protocol::TLS13,
        true,
        None,
        "CIPHER",
        Grade::A,
        None,
        None,
        None,
    );
    let scan2 = make_scan(
        Protocol::TLS13,
        false,
        None,
        "CIPHER",
        Grade::A,
        None,
        None,
        None,
    );

    let mut results = HashMap::new();
    results.insert(
        ip1,
        SingleIpScanResult {
            ip: ip1,
            scan_result: scan1,
            scan_duration_ms: 100,
            error: None,
        },
    );
    results.insert(
        ip2,
        SingleIpScanResult {
            ip: ip2,
            scan_result: scan2,
            scan_duration_ms: 120,
            error: None,
        },
    );
    results.insert(
        ip3,
        SingleIpScanResult {
            ip: ip3,
            scan_result: ScanResults::default(),
            scan_duration_ms: 80,
            error: Some("timeout".to_string()),
        },
    );

    let detector = InconsistencyDetector::new(results);
    let inconsistencies = detector.detect_all();

    let protocol_inconsistency = inconsistencies
        .into_iter()
        .find(|inconsistency| {
            matches!(
                inconsistency.details,
                InconsistencyDetails::Protocols {
                    protocol: Protocol::TLS13,
                    ..
                }
            )
        })
        .expect("protocol inconsistency should be detected");

    assert_eq!(
        protocol_inconsistency.description,
        "TLS 1.3 support is inconsistent across backends (1/2 IPs support it)"
    );
}

#[test]
fn test_single_ip_scan_result_success_flag() {
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let scan = make_scan(
        Protocol::TLS12,
        true,
        None,
        "CIPHER",
        Grade::A,
        None,
        None,
        None,
    );

    let ok = SingleIpScanResult {
        ip,
        scan_result: scan,
        scan_duration_ms: 1,
        error: None,
    };
    assert!(ok.is_successful());

    let failed = SingleIpScanResult {
        ip,
        scan_result: ScanResults::default(),
        scan_duration_ms: 1,
        error: Some("boom".to_string()),
    };
    assert!(!failed.is_successful());
}
