use super::*;
use crate::Args;
use crate::certificates::parser::{CertificateChain, CertificateInfo};
use crate::certificates::validator::ValidationResult;
use crate::client_sim::simulator::ClientSimulationResult;
use crate::fingerprint::{Ja3Fingerprint, Ja3Signature};
use crate::http::tester::{HeaderAnalysisResult, SecurityGrade};
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::utils::network::Target;
use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn test_scan_results_json() {
    let results = ScanResults {
        target: "example.com:443".to_string(),
        scan_time_ms: 1234,
        ..Default::default()
    };

    let json = results
        .to_json(false)
        .expect("test assertion should succeed");
    assert!(json.contains("example.com"));
}

#[test]
fn test_scan_results_csv() {
    let results = ScanResults::default();
    let csv = results.to_csv().expect("test assertion should succeed");
    assert!(csv.contains("Type,Severity"));
}

#[test]
fn test_scan_results_accessors_and_mutators() {
    let mut results = ScanResults::default();

    results.http_mut().http_headers = Some(HeaderAnalysisResult {
        headers: HashMap::new(),
        issues: vec![],
        score: 100,
        grade: SecurityGrade::A,
        hsts_analysis: None,
        hpkp_analysis: None,
        cookie_analysis: None,
        datetime_check: None,
        banner_detection: None,
        reverse_proxy_detection: None,
        http_status_code: None,
        redirect_location: None,
        redirect_chain: vec![],
        server_hostname: None,
    });
    results.rating_mut().ssl_rating = Some(crate::rating::scoring::RatingResult {
        grade: crate::rating::grader::Grade::A,
        score: 95,
        certificate_score: 90,
        protocol_score: 95,
        key_exchange_score: 95,
        cipher_strength_score: 95,
        warnings: vec![],
    });
    results.fingerprints_mut().ja3_fingerprint = Some(Ja3Fingerprint {
        ja3_string: "771,4865-4866,0-11-10,29-23,0".to_string(),
        ja3_hash: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ssl_version: 771,
        ciphers: vec![4865, 4866],
        extensions: vec![0, 11, 10],
        curves: vec![29, 23],
        point_formats: vec![0],
    });
    results.fingerprints_mut().ja3_match = Some(Ja3Signature {
        name: "Test".to_string(),
        category: "Tool".to_string(),
        description: "Synthetic".to_string(),
        threat_level: "none".to_string(),
    });
    results.advanced_mut().client_simulations = Some(vec![ClientSimulationResult {
        client_name: "TestClient".to_string(),
        client_id: "test".to_string(),
        success: true,
        protocol: None,
        cipher: None,
        error: None,
        handshake_time_ms: Some(5),
        alpn: None,
        key_exchange: None,
        forward_secrecy: false,
        certificate_type: None,
    }]);

    assert!(results.http_headers().is_some());
    assert!(results.ssl_rating().is_some());
    assert!(results.ja3_fingerprint().is_some());
    assert!(results.ja3_match().is_some());
    assert!(results.client_simulations().is_some());
}

#[test]
fn test_scan_results_connection_evidence_requires_successful_subtests() {
    let mut results = ScanResults::default();
    results.advanced_mut().alpn_result = Some(crate::protocols::alpn::AlpnReport {
        alpn_enabled: false,
        alpn_result: crate::protocols::alpn::AlpnResult {
            supported_protocols: vec![],
            http2_supported: false,
            http3_supported: false,
            negotiated_protocol: None,
            details: vec![],
        },
        spdy_supported: false,
        recommendations: vec![],
    });
    results.advanced_mut().client_simulations = Some(vec![ClientSimulationResult {
        client_name: "TestClient".to_string(),
        client_id: "test".to_string(),
        success: false,
        protocol: None,
        cipher: None,
        error: Some("failed".to_string()),
        handshake_time_ms: None,
        alpn: None,
        key_exchange: None,
        forward_secrecy: false,
        certificate_type: None,
    }]);

    assert!(!results.has_connection_evidence());

    results.advanced_mut().signature_algorithms =
        Some(crate::protocols::signatures::SignatureEnumerationResult {
            algorithms: vec![crate::protocols::signatures::SignatureAlgorithm {
                name: "rsa_pkcs1_sha256".to_string(),
                iana_value: 0x0401,
                supported: false,
            }],
        });
    results.advanced_mut().key_exchange_groups =
        Some(crate::protocols::groups::GroupEnumerationResult {
            groups: vec![crate::protocols::groups::KeyExchangeGroup {
                name: "x25519".to_string(),
                iana_value: 29,
                group_type: crate::protocols::groups::GroupType::EllipticCurve,
                bits: 253,
                supported: false,
            }],
            measured: false,
            details: "No negotiation".to_string(),
        });
    results.advanced_mut().client_cas = Some(crate::protocols::client_cas::ClientCAsResult {
        cas: vec![],
        requires_client_auth: false,
    });
    results.advanced_mut().intolerance =
        Some(crate::protocols::intolerance::IntoleranceTestResult::default());
    results.advanced_mut().alpn_result = Some(crate::protocols::alpn::AlpnReport {
        alpn_enabled: false,
        alpn_result: crate::protocols::alpn::AlpnResult {
            supported_protocols: vec![],
            http2_supported: false,
            http3_supported: false,
            negotiated_protocol: None,
            details: vec![],
        },
        spdy_supported: false,
        recommendations: vec![],
    });

    assert!(!results.has_connection_evidence());

    results.advanced_mut().client_simulations = Some(vec![ClientSimulationResult {
        client_name: "TestClient".to_string(),
        client_id: "test".to_string(),
        success: true,
        protocol: Some(Protocol::TLS13),
        cipher: Some("TLS_AES_128_GCM_SHA256".to_string()),
        error: None,
        handshake_time_ms: Some(8),
        alpn: Some("h2".to_string()),
        key_exchange: Some("x25519".to_string()),
        forward_secrecy: true,
        certificate_type: Some("RSA 2048".to_string()),
    }]);
    assert!(results.has_connection_evidence());
}

#[test]
fn test_scan_results_csv_with_vulnerability() {
    let vuln = VulnerabilityResult {
        vuln_type: VulnerabilityType::ROBOT,
        vulnerable: true,
        inconclusive: false,
        details: "Comma, should be replaced".to_string(),
        cve: Some("CVE-2017-13099".to_string()),
        cwe: None,
        severity: Severity::High,
    };

    let results = ScanResults {
        vulnerabilities: vec![vuln],
        ..Default::default()
    };

    let csv = results.to_csv().expect("test assertion should succeed");
    assert!(csv.contains("ROBOT"));
    assert!(csv.contains("CVE-2017-13099"));
    assert!(csv.contains("Comma; should be replaced"));
}

#[test]
fn test_scan_results_connection_evidence_treats_completed_vulnerability_batch_as_signal() {
    let results = ScanResults {
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::ROBOT,
            vulnerable: false,
            inconclusive: false,
            details: "Not vulnerable".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Info,
        }],
        ..Default::default()
    };

    assert!(results.has_connection_evidence());
}

#[test]
fn test_aggregate_vulnerabilities_merges_by_type() {
    let mut results = HashMap::new();

    let scan_a = ScanResults {
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: false,
            inconclusive: false,
            details: "Not vulnerable".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Info,
        }],
        ..Default::default()
    };

    let scan_b = ScanResults {
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: true,
            inconclusive: false,
            details: "RC4 supported".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        }],
        ..Default::default()
    };

    results.insert(
        "127.0.0.1".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.1".parse().unwrap(),
            scan_result: scan_a,
            scan_duration_ms: 10,
            error: None,
        },
    );
    results.insert(
        "127.0.0.2".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.2".parse().unwrap(),
            scan_result: scan_b,
            scan_duration_ms: 12,
            error: None,
        },
    );

    let aggregated = Scanner::aggregate_vulnerabilities(&results);
    assert_eq!(aggregated.len(), 1);
    assert!(aggregated[0].vulnerable);
    assert_eq!(aggregated[0].severity, Severity::Medium);
}

#[test]
fn test_aggregate_vulnerabilities_preserves_all_detail_segments_deterministically() {
    let ip1: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    let scan_short = ScanResults {
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: true,
            inconclusive: false,
            details: "TLS 1.2".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        }],
        ..Default::default()
    };

    let scan_long = ScanResults {
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: true,
            inconclusive: false,
            details: "TLS 1.2 support".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        }],
        ..Default::default()
    };

    let mut results_a = HashMap::new();
    results_a.insert(
        ip1,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip1,
            scan_result: scan_short.clone(),
            scan_duration_ms: 10,
            error: None,
        },
    );
    results_a.insert(
        ip2,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip2,
            scan_result: scan_long.clone(),
            scan_duration_ms: 12,
            error: None,
        },
    );

    let mut results_b = HashMap::new();
    results_b.insert(
        ip2,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip2,
            scan_result: scan_long,
            scan_duration_ms: 12,
            error: None,
        },
    );
    results_b.insert(
        ip1,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip1,
            scan_result: scan_short,
            scan_duration_ms: 10,
            error: None,
        },
    );

    let aggregated_a = Scanner::aggregate_vulnerabilities(&results_a);
    let aggregated_b = Scanner::aggregate_vulnerabilities(&results_b);

    assert_eq!(aggregated_a.len(), 1);
    assert_eq!(aggregated_b.len(), 1);
    assert_eq!(aggregated_a[0].details, "TLS 1.2; TLS 1.2 support");
    assert_eq!(aggregated_a[0].details, aggregated_b[0].details);
    assert!(aggregated_a[0].details.contains("TLS 1.2"));
    assert!(aggregated_a[0].details.contains("TLS 1.2 support"));
}

#[test]
fn test_aggregate_vulnerabilities_marks_results_inconclusive_when_backend_fails() {
    let ip1: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    let successful_scan = ScanResults {
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: false,
            inconclusive: false,
            details: "Not vulnerable".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Info,
        }],
        ..Default::default()
    };

    let mut results = HashMap::new();
    results.insert(
        ip1,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip1,
            scan_result: successful_scan,
            scan_duration_ms: 10,
            error: None,
        },
    );
    results.insert(
        ip2,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip2,
            scan_result: ScanResults::default(),
            scan_duration_ms: 11,
            error: Some("connection reset".to_string()),
        },
    );

    let aggregated = Scanner::aggregate_vulnerabilities(&results);

    assert_eq!(aggregated.len(), 1);
    assert!(!aggregated[0].vulnerable);
    assert!(aggregated[0].inconclusive);
    assert!(
        aggregated[0]
            .details
            .contains("incomplete backend coverage")
    );
}

#[test]
fn test_select_common_certificate_chain_prefers_matching_fingerprint() {
    let mut results = HashMap::new();

    let leaf_a = CertificateInfo {
        fingerprint_sha256: Some("AA".to_string()),
        ..Default::default()
    };
    let chain_a = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![leaf_a],
            chain_length: 1,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    let leaf_b = CertificateInfo {
        fingerprint_sha256: Some("BB".to_string()),
        ..Default::default()
    };
    let chain_b = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![leaf_b.clone()],
            chain_length: 1,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    let scan_a = ScanResults {
        certificate_chain: Some(chain_a),
        ..Default::default()
    };
    let scan_b = ScanResults {
        certificate_chain: Some(chain_b.clone()),
        ..Default::default()
    };

    results.insert(
        "127.0.0.1".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.1".parse().unwrap(),
            scan_result: scan_a,
            scan_duration_ms: 10,
            error: None,
        },
    );
    results.insert(
        "127.0.0.2".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.2".parse().unwrap(),
            scan_result: scan_b,
            scan_duration_ms: 12,
            error: None,
        },
    );

    let cert_info = leaf_b;
    let selected = Scanner::select_common_certificate_chain(&results, Some(&cert_info));
    assert!(selected.is_some());
    let selected = selected.expect("test assertion should succeed");
    let leaf = selected
        .chain
        .leaf()
        .expect("test assertion should succeed");
    assert_eq!(leaf.fingerprint_sha256.as_deref(), Some("BB"));
}

#[test]
fn test_select_common_certificate_chain_prefers_majority_full_chain_for_same_leaf() {
    let mut results = HashMap::new();

    let leaf = CertificateInfo {
        fingerprint_sha256: Some("AA".to_string()),
        ..Default::default()
    };
    let intermediate_a = CertificateInfo {
        fingerprint_sha256: Some("IA".to_string()),
        subject: "CN=intermediate-a".to_string(),
        issuer: "CN=root".to_string(),
        is_ca: true,
        ..Default::default()
    };
    let intermediate_b = CertificateInfo {
        fingerprint_sha256: Some("IB".to_string()),
        subject: "CN=intermediate-b".to_string(),
        issuer: "CN=root".to_string(),
        is_ca: true,
        ..Default::default()
    };
    let root = CertificateInfo {
        fingerprint_sha256: Some("RR".to_string()),
        subject: "CN=root".to_string(),
        issuer: "CN=root".to_string(),
        is_ca: true,
        ..Default::default()
    };

    let chain_a = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![leaf.clone(), intermediate_a.clone(), root.clone()],
            chain_length: 3,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };
    let chain_b = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![leaf.clone(), intermediate_b.clone(), root.clone()],
            chain_length: 3,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    results.insert(
        "127.0.0.2".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.2".parse().unwrap(),
            scan_result: ScanResults {
                certificate_chain: Some(chain_a.clone()),
                ..Default::default()
            },
            scan_duration_ms: 10,
            error: None,
        },
    );
    results.insert(
        "127.0.0.3".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.3".parse().unwrap(),
            scan_result: ScanResults {
                certificate_chain: Some(chain_a.clone()),
                ..Default::default()
            },
            scan_duration_ms: 12,
            error: None,
        },
    );
    results.insert(
        "127.0.0.1".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.1".parse().unwrap(),
            scan_result: ScanResults {
                certificate_chain: Some(chain_b),
                ..Default::default()
            },
            scan_duration_ms: 14,
            error: None,
        },
    );

    let cert_info = leaf;
    let selected = Scanner::select_common_certificate_chain(&results, Some(&cert_info))
        .expect("expected a certificate chain");

    assert_eq!(
        selected.chain.intermediates().len(),
        1,
        "expected the majority chain to be selected"
    );
    assert_eq!(
        selected.chain.intermediates()[0]
            .fingerprint_sha256
            .as_deref(),
        Some("IA")
    );
}

#[test]
fn test_select_chain_by_fingerprint_uses_sorted_chain_order() {
    let low_leaf = CertificateInfo {
        fingerprint_sha256: Some("AA".to_string()),
        subject: "CN=low-ip".to_string(),
        ..Default::default()
    };
    let low_chain = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![low_leaf],
            chain_length: 1,
            chain_size_bytes: 111,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    let high_leaf = CertificateInfo {
        fingerprint_sha256: Some("AA".to_string()),
        subject: "CN=high-ip".to_string(),
        ..Default::default()
    };
    let high_chain = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![high_leaf],
            chain_length: 1,
            chain_size_bytes: 222,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    let selected = Scanner::select_chain_by_fingerprint(&[low_chain.clone(), high_chain], "AA")
        .expect("expected a matching chain");

    assert_eq!(selected.chain.chain_size_bytes, 111);
    assert_eq!(selected.chain.leaf().unwrap().subject, "CN=low-ip");
}

#[test]
fn test_select_common_certificate_chain_fallback_to_first_success() {
    let mut results = HashMap::new();

    let leaf = CertificateInfo {
        fingerprint_sha256: Some("CC".to_string()),
        ..Default::default()
    };
    let chain = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![leaf.clone()],
            chain_length: 1,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    let scan = ScanResults {
        certificate_chain: Some(chain.clone()),
        ..Default::default()
    };

    results.insert(
        "127.0.0.1".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.1".parse().unwrap(),
            scan_result: scan,
            scan_duration_ms: 5,
            error: None,
        },
    );

    let selected = Scanner::select_common_certificate_chain(&results, None);
    assert!(selected.is_some());
    assert_eq!(
        selected.unwrap().chain.leaf().unwrap().fingerprint_sha256,
        Some("CC".to_string())
    );
}

#[test]
fn test_select_common_certificate_chain_is_deterministic_without_fingerprint() {
    let mut results = HashMap::new();

    let low_leaf = CertificateInfo {
        fingerprint_sha256: Some("AA".to_string()),
        ..Default::default()
    };
    let low_chain = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![low_leaf.clone()],
            chain_length: 1,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    let high_leaf = CertificateInfo {
        fingerprint_sha256: Some("BB".to_string()),
        ..Default::default()
    };
    let high_chain = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![high_leaf.clone()],
            chain_length: 1,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    results.insert(
        "127.0.0.2".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.2".parse().unwrap(),
            scan_result: ScanResults {
                certificate_chain: Some(high_chain),
                ..Default::default()
            },
            scan_duration_ms: 12,
            error: None,
        },
    );
    results.insert(
        "127.0.0.1".parse().unwrap(),
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: "127.0.0.1".parse().unwrap(),
            scan_result: ScanResults {
                certificate_chain: Some(low_chain),
                ..Default::default()
            },
            scan_duration_ms: 10,
            error: None,
        },
    );

    let selected = Scanner::select_common_certificate_chain(&results, None)
        .expect("lowest IP should be selected deterministically");
    assert_eq!(
        selected.chain.leaf().unwrap().fingerprint_sha256,
        Some("AA".to_string())
    );
}

#[test]
fn test_scan_results_advanced_accessors() {
    let mut results = ScanResults::default();
    results.fingerprints_mut().ja3s_fingerprint = Some(crate::fingerprint::Ja3sFingerprint {
        ja3s_string: "771,4865,0-10".to_string(),
        ja3s_hash: "abc".to_string(),
        ssl_version: 771,
        cipher: 4865,
        extensions: vec![0, 10],
    });
    results.fingerprints_mut().ja3s_match = Some(crate::fingerprint::Ja3sSignature {
        name: "Test".to_string(),
        server_type: crate::fingerprint::ja3s::ServerType::WebServer,
        description: "desc".to_string(),
        common_ports: vec![443],
        indicators: vec![],
    });
    results.fingerprints_mut().jarm_fingerprint = Some(crate::fingerprint::JarmFingerprint {
        hash: "hash".to_string(),
        raw_responses: vec![],
        signature: None,
    });
    results.advanced_mut().alpn_result = Some(crate::protocols::alpn::AlpnReport {
        alpn_enabled: false,
        alpn_result: crate::protocols::alpn::AlpnResult {
            supported_protocols: vec![],
            http2_supported: false,
            http3_supported: false,
            negotiated_protocol: None,
            details: vec![],
        },
        spdy_supported: false,
        recommendations: vec![],
    });
    results.advanced_mut().signature_algorithms =
        Some(crate::protocols::signatures::SignatureEnumerationResult { algorithms: vec![] });
    results.advanced_mut().key_exchange_groups =
        Some(crate::protocols::groups::GroupEnumerationResult {
            groups: vec![],
            measured: false,
            details: String::new(),
        });
    results.advanced_mut().client_cas = Some(crate::protocols::client_cas::ClientCAsResult {
        cas: vec![],
        requires_client_auth: false,
    });

    assert!(results.ja3s_fingerprint().is_some());
    assert!(results.ja3s_match().is_some());
    assert!(results.jarm_fingerprint().is_some());
    assert!(results.alpn_result().is_some());
    assert!(results.signature_algorithms().is_some());
    assert!(results.key_exchange_groups().is_some());
    assert!(results.client_cas().is_some());
}

#[test]
fn test_build_conservative_multi_ip_result() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: crate::cli::ScanArgs {
            all: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

    let leaf = CertificateInfo {
        fingerprint_sha256: Some("AA".to_string()),
        ..Default::default()
    };
    let chain = CertificateAnalysisResult {
        chain: CertificateChain {
            certificates: vec![leaf.clone()],
            chain_length: 1,
            chain_size_bytes: 0,
        },
        validation: ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        },
        revocation: None,
    };

    let scan_result = ScanResults {
        target: "192.0.2.10:443".to_string(),
        certificate_chain: Some(chain),
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: true,
            inconclusive: false,
            details: "RC4 supported".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::High,
        }],
        ..Default::default()
    };

    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(
        ip,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip,
            scan_result,
            scan_duration_ms: 10,
            error: None,
        },
    );

    let aggregated = crate::scanner::aggregation::AggregatedScanResult {
        protocols: Vec::new(),
        ciphers: HashMap::new(),
        grade: ("F".to_string(), 0),
        certificate_info: Some(leaf),
        certificate_consistent: true,
        inconsistencies: Vec::new(),
        alpn_protocols: Vec::new(),
        session_resumption_caching: Some(false),
        session_resumption_tickets: Some(false),
    };

    let report = crate::scanner::multi_ip::MultiIpScanReport {
        target: Target::with_ips("example.com".to_string(), 443, vec![ip])
            .expect("test assertion should succeed"),
        per_ip_results,
        total_ips: 1,
        successful_scans: 1,
        failed_scans: 0,
        total_duration_ms: 10,
        inconsistencies: Vec::new(),
        aggregated,
    };

    let result = scanner
        .build_conservative_multi_ip_result(&report)
        .expect("test assertion should succeed");
    assert_eq!(result.target, "example.com:443");
    assert_eq!(result.vulnerabilities.len(), 1);
    assert!(result.certificate_chain.is_some());
    assert!(result.rating.is_some());
}

#[test]
fn test_build_conservative_multi_ip_result_respects_disable_rating() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: crate::cli::ScanArgs {
            all: true,
            disable_rating: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let scan_result = ScanResults {
        target: "example.com:443".to_string(),
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };

    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(
        ip,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip,
            scan_result,
            scan_duration_ms: 10,
            error: None,
        },
    );

    let report = crate::scanner::multi_ip::MultiIpScanReport {
        target: Target::with_ips("example.com".to_string(), 443, vec![ip])
            .expect("test assertion should succeed"),
        per_ip_results,
        total_ips: 1,
        successful_scans: 1,
        failed_scans: 0,
        total_duration_ms: 10,
        inconsistencies: Vec::new(),
        aggregated: crate::scanner::aggregation::AggregatedScanResult {
            protocols: Vec::new(),
            ciphers: HashMap::new(),
            grade: ("F".to_string(), 0),
            certificate_info: None,
            certificate_consistent: true,
            inconsistencies: Vec::new(),
            alpn_protocols: Vec::new(),
            session_resumption_caching: Some(false),
            session_resumption_tickets: Some(false),
        },
    };

    let result = scanner
        .build_conservative_multi_ip_result(&report)
        .expect("test assertion should succeed");

    assert!(result.rating.is_none());
}

#[test]
fn test_build_conservative_multi_ip_result_aggregates_probe_metadata() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: crate::cli::ScanArgs {
            all: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

    let ip1: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    let slow_result = ScanResults {
        scan_metadata: ScanMetadata {
            probe_status: ProbeStatus::success(Duration::from_millis(25)),
            pre_handshake_used: false,
            ..Default::default()
        },
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };

    let fast_result = ScanResults {
        scan_metadata: ScanMetadata {
            probe_status: ProbeStatus::success(Duration::from_millis(8)),
            pre_handshake_used: true,
            ..Default::default()
        },
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(4),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };

    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(
        ip1,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip1,
            scan_result: slow_result,
            scan_duration_ms: 25,
            error: None,
        },
    );
    per_ip_results.insert(
        ip2,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip2,
            scan_result: fast_result,
            scan_duration_ms: 8,
            error: None,
        },
    );

    let aggregated = crate::scanner::aggregation::AggregatedScanResult {
        protocols: Vec::new(),
        ciphers: HashMap::new(),
        grade: ("F".to_string(), 0),
        certificate_info: None,
        certificate_consistent: true,
        inconsistencies: Vec::new(),
        alpn_protocols: Vec::new(),
        session_resumption_caching: Some(false),
        session_resumption_tickets: Some(false),
    };

    let report = crate::scanner::multi_ip::MultiIpScanReport {
        target: Target::with_ips("example.com".to_string(), 443, vec![ip1, ip2])
            .expect("test assertion should succeed"),
        per_ip_results,
        total_ips: 2,
        successful_scans: 2,
        failed_scans: 0,
        total_duration_ms: 33,
        inconsistencies: Vec::new(),
        aggregated,
    };

    let result = scanner
        .build_conservative_multi_ip_result(&report)
        .expect("test assertion should succeed");

    assert!(result.scan_metadata.probe_status.success);
    assert_eq!(
        result.scan_metadata.probe_status.connection_time_ms,
        Some(8)
    );
    assert_eq!(result.scan_metadata.probe_status.attempts, 2);
    assert!(result.scan_metadata.pre_handshake_used);
}

#[test]
fn test_build_conservative_multi_ip_result_keeps_success_with_failed_ips() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: crate::cli::ScanArgs {
            all: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

    let ip1: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    let successful_result = ScanResults {
        scan_metadata: ScanMetadata {
            probe_status: ProbeStatus::success(Duration::from_millis(11)),
            ..Default::default()
        },
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };

    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(
        ip1,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip1,
            scan_result: successful_result,
            scan_duration_ms: 11,
            error: None,
        },
    );
    per_ip_results.insert(
        ip2,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip2,
            scan_result: ScanResults::default(),
            scan_duration_ms: 50,
            error: Some("timeout".to_string()),
        },
    );

    let aggregated = crate::scanner::aggregation::AggregatedScanResult {
        protocols: Vec::new(),
        ciphers: HashMap::new(),
        grade: ("F".to_string(), 0),
        certificate_info: None,
        certificate_consistent: true,
        inconsistencies: Vec::new(),
        alpn_protocols: Vec::new(),
        session_resumption_caching: Some(false),
        session_resumption_tickets: Some(false),
    };

    let report = crate::scanner::multi_ip::MultiIpScanReport {
        target: Target::with_ips("example.com".to_string(), 443, vec![ip1, ip2])
            .expect("test assertion should succeed"),
        per_ip_results,
        total_ips: 2,
        successful_scans: 1,
        failed_scans: 1,
        total_duration_ms: 61,
        inconsistencies: Vec::new(),
        aggregated,
    };

    let result = scanner
        .build_conservative_multi_ip_result(&report)
        .expect("test assertion should succeed");

    assert!(result.scan_metadata.probe_status.success);
    assert_eq!(
        result.scan_metadata.probe_status.error_type,
        Some(crate::scanner::probe_status::ErrorType::Warning)
    );
    assert_eq!(
        result.scan_metadata.probe_status.connection_time_ms,
        Some(11)
    );
    assert_eq!(result.scan_metadata.probe_status.attempts, 1);
}

#[test]
fn test_build_conservative_multi_ip_result_uses_stable_probe_fallback() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: crate::cli::ScanArgs {
            all: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

    let ip_low: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let ip_high: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    let fallback_low = ScanResults {
        scan_metadata: ScanMetadata {
            probe_status: ProbeStatus::failure_string(
                "low-ip".to_string(),
                crate::scanner::probe_status::ErrorType::Timeout,
            ),
            ..Default::default()
        },
        ..Default::default()
    };

    let fallback_high = ScanResults {
        scan_metadata: ScanMetadata {
            probe_status: ProbeStatus::failure_string(
                "high-ip".to_string(),
                crate::scanner::probe_status::ErrorType::Timeout,
            ),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(
        ip_high,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip_high,
            scan_result: fallback_high,
            scan_duration_ms: 9,
            error: None,
        },
    );
    per_ip_results.insert(
        ip_low,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip: ip_low,
            scan_result: fallback_low,
            scan_duration_ms: 7,
            error: None,
        },
    );

    let aggregated = crate::scanner::aggregation::AggregatedScanResult {
        protocols: Vec::new(),
        ciphers: HashMap::new(),
        grade: ("F".to_string(), 0),
        certificate_info: None,
        certificate_consistent: true,
        inconsistencies: Vec::new(),
        alpn_protocols: Vec::new(),
        session_resumption_caching: Some(false),
        session_resumption_tickets: Some(false),
    };

    let report = crate::scanner::multi_ip::MultiIpScanReport {
        target: Target::with_ips("example.com".to_string(), 443, vec![ip_high, ip_low])
            .expect("test assertion should succeed"),
        per_ip_results,
        total_ips: 2,
        successful_scans: 2,
        failed_scans: 0,
        total_duration_ms: 16,
        inconsistencies: Vec::new(),
        aggregated,
    };

    let result = scanner
        .build_conservative_multi_ip_result(&report)
        .expect("test assertion should succeed");

    assert_eq!(
        result.scan_metadata.probe_status.error.as_deref(),
        Some("low-ip")
    );
    assert_eq!(result.scan_metadata.probe_status.attempts, 2);
}

#[test]
fn test_build_conservative_multi_ip_result_partial_success_without_probe_attempts() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: crate::cli::ScanArgs {
            all: true,
            disable_rating: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let scan_result = ScanResults {
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };

    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(
        ip,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip,
            scan_result,
            scan_duration_ms: 9,
            error: None,
        },
    );

    let report = crate::scanner::multi_ip::MultiIpScanReport {
        target: Target::with_ips("example.com".to_string(), 443, vec![ip])
            .expect("test assertion should succeed"),
        per_ip_results,
        total_ips: 1,
        successful_scans: 1,
        failed_scans: 0,
        total_duration_ms: 9,
        inconsistencies: Vec::new(),
        aggregated: crate::scanner::aggregation::AggregatedScanResult {
            protocols: Vec::new(),
            ciphers: HashMap::new(),
            grade: ("F".to_string(), 0),
            certificate_info: None,
            certificate_consistent: true,
            inconsistencies: Vec::new(),
            alpn_protocols: Vec::new(),
            session_resumption_caching: Some(false),
            session_resumption_tickets: Some(false),
        },
    };

    let result = scanner
        .build_conservative_multi_ip_result(&report)
        .expect("test assertion should succeed");

    assert!(result.scan_metadata.probe_status.success);
    assert_eq!(
        result.scan_metadata.probe_status.error_type,
        Some(crate::scanner::probe_status::ErrorType::Warning)
    );
    assert_eq!(
        result.scan_metadata.probe_status.connection_time_ms,
        Some(0)
    );
    assert_eq!(result.scan_metadata.probe_status.attempts, 0);
}

#[test]
fn test_build_conservative_multi_ip_result_clears_unaggregated_residual_sections() {
    let args = Args {
        target: Some("example.com".to_string()),
        scan: crate::cli::ScanArgs {
            all: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    let mut scan_result = ScanResults {
        target: "example.com:443".to_string(),
        protocols: vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }],
        ..Default::default()
    };
    scan_result.http_mut().http_headers = Some(HeaderAnalysisResult {
        headers: HashMap::new(),
        issues: vec![],
        score: 100,
        grade: SecurityGrade::A,
        hsts_analysis: None,
        hpkp_analysis: None,
        cookie_analysis: None,
        datetime_check: None,
        banner_detection: None,
        reverse_proxy_detection: None,
        http_status_code: None,
        redirect_location: None,
        redirect_chain: vec![],
        server_hostname: None,
    });
    scan_result.fingerprints_mut().ja3_fingerprint = Some(Ja3Fingerprint {
        ja3_string: "771,4865-4866,0-11-10,29-23,0".to_string(),
        ja3_hash: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ssl_version: 771,
        ciphers: vec![4865, 4866],
        extensions: vec![0, 11, 10],
        curves: vec![29, 23],
        point_formats: vec![0],
    });
    scan_result.fingerprints_mut().ja3_match = Some(Ja3Signature {
        name: "Test".to_string(),
        category: "Tool".to_string(),
        description: "Synthetic".to_string(),
        threat_level: "none".to_string(),
    });
    scan_result.advanced_mut().client_simulations = Some(vec![ClientSimulationResult {
        client_name: "TestClient".to_string(),
        client_id: "test".to_string(),
        success: true,
        protocol: None,
        cipher: None,
        error: None,
        handshake_time_ms: Some(5),
        alpn: None,
        key_exchange: None,
        forward_secrecy: false,
        certificate_type: None,
    }]);
    scan_result.advanced_mut().alpn_result = Some(crate::protocols::alpn::AlpnReport {
        alpn_enabled: true,
        alpn_result: crate::protocols::alpn::AlpnResult {
            supported_protocols: vec!["h2".to_string()],
            http2_supported: true,
            http3_supported: false,
            negotiated_protocol: Some("h2".to_string()),
            details: vec!["Server prefers: h2".to_string()],
        },
        spdy_supported: false,
        recommendations: vec![],
    });
    scan_result.advanced_mut().signature_algorithms =
        Some(crate::protocols::signatures::SignatureEnumerationResult { algorithms: vec![] });
    scan_result.advanced_mut().key_exchange_groups =
        Some(crate::protocols::groups::GroupEnumerationResult {
            groups: vec![],
            measured: false,
            details: String::new(),
        });
    scan_result.advanced_mut().client_cas = Some(crate::protocols::client_cas::ClientCAsResult {
        cas: vec![],
        requires_client_auth: false,
    });
    scan_result.advanced_mut().intolerance =
        Some(crate::protocols::intolerance::IntoleranceTestResult {
            extension_intolerance: false,
            version_intolerance: false,
            long_handshake_intolerance: false,
            incorrect_sni_alerts: false,
            uses_common_dh_primes: false,
            details: HashMap::new(),
        });

    let mut per_ip_results = HashMap::new();
    per_ip_results.insert(
        ip,
        crate::scanner::inconsistency::SingleIpScanResult {
            ip,
            scan_result,
            scan_duration_ms: 10,
            error: None,
        },
    );

    let report = crate::scanner::multi_ip::MultiIpScanReport {
        target: Target::with_ips("example.com".to_string(), 443, vec![ip])
            .expect("test assertion should succeed"),
        per_ip_results,
        total_ips: 1,
        successful_scans: 1,
        failed_scans: 0,
        total_duration_ms: 10,
        inconsistencies: Vec::new(),
        aggregated: crate::scanner::aggregation::AggregatedScanResult {
            protocols: Vec::new(),
            ciphers: HashMap::new(),
            grade: ("F".to_string(), 0),
            certificate_info: None,
            certificate_consistent: true,
            inconsistencies: Vec::new(),
            alpn_protocols: Vec::new(),
            session_resumption_caching: Some(false),
            session_resumption_tickets: Some(false),
        },
    };

    let result = scanner
        .build_conservative_multi_ip_result(&report)
        .expect("test assertion should succeed");

    assert!(result.http_headers().is_none());
    assert!(result.ja3_fingerprint().is_none());
    assert!(result.client_simulations().is_none());
    assert!(result.alpn_result().is_none());
    assert!(result.signature_algorithms().is_none());
    assert!(result.key_exchange_groups().is_none());
    assert!(result.client_cas().is_none());
    assert!(result.intolerance().is_none());
}

#[test]
fn test_scanner_new_requires_target() {
    let args = Args::default();
    let err = Scanner::new(args.to_scan_request())
        .err()
        .expect("should error");
    assert!(
        err.to_string()
            .contains("A target is required for scan execution")
    );
}
