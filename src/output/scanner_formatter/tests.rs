use super::*;
use crate::certificates::parser::{CertificateChain, CertificateInfo};
use crate::certificates::revocation::{RevocationMethod, RevocationResult, RevocationStatus};
use crate::certificates::trust_stores::{
    PlatformTrustStatus, TrustStore, TrustValidationResult, ValidationDetails,
};
use crate::certificates::validator::{IssueSeverity, IssueType, ValidationIssue, ValidationResult};
use crate::ciphers::CipherSuite;
use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use crate::client_sim::simulator::ClientSimulationResult;
use crate::fingerprint::ja3s::ServerType;
use crate::fingerprint::{
    Ja3Fingerprint, Ja3Signature, Ja3sFingerprint, Ja3sSignature, JarmFingerprint, JarmSignature,
};
use crate::http::headers::{
    HeaderIssue, IssueSeverity as HeaderSeverity, IssueType as HeaderIssueType,
};
use crate::http::headers_advanced::{
    BannerDetection, CookieAnalysis, CookieInfo, DateTimeCheck, Grade as HeaderGrade, HpkpAnalysis,
    HstsAnalysis, ReverseProxyDetection,
};
use crate::http::tester::{HeaderAnalysisResult, SecurityGrade};
use crate::pqc::{PqcLevel, PqcReadinessAssessment};
use crate::protocols::alpn::{AlpnReport, AlpnResult};
use crate::protocols::client_cas::{ClientCA, ClientCAsResult};
use crate::protocols::groups::{GroupEnumerationResult, GroupType, KeyExchangeGroup};
use crate::protocols::intolerance::IntoleranceTestResult;
use crate::protocols::signatures::{SignatureAlgorithm, SignatureEnumerationResult};
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::rating::RatingResult;
use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};
use std::collections::HashMap;

#[test]
fn test_scanner_formatter_creation() {
    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);
    assert!(!formatter.args.output.show_times);
}

#[test]
fn test_collect_human_warnings_includes_rating_certificate_and_inconclusive_vulns() {
    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);

    let cert = CertificateInfo {
        debian_weak_key: Some(true),
        ..Default::default()
    };

    let results = crate::scanner::ScanResults {
        certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
            chain: CertificateChain {
                certificates: vec![cert],
                chain_length: 1,
                chain_size_bytes: 1,
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
        }),
        rating: Some(crate::scanner::RatingResults {
            ssl_rating: Some(RatingResult {
                grade: crate::rating::Grade::B,
                score: 80,
                certificate_score: 80,
                protocol_score: 80,
                key_exchange_score: 80,
                cipher_strength_score: 80,
                warnings: vec!["Weak protocol mix".to_string()],
            }),
        }),
        vulnerabilities: vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: false,
            inconclusive: true,
            details: "handshake failed".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::High,
        }],
        ..Default::default()
    };

    let warnings = formatter.collect_human_warnings(&results);
    assert!(
        warnings
            .iter()
            .any(|warning| warning == "Weak protocol mix")
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("Debian weak key detected"))
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("Heartbleed") && warning.contains("inconclusive"))
    );
}

#[test]
fn test_collect_human_warnings_includes_structured_runtime_warnings_once() {
    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);

    let mut results = crate::scanner::ScanResults::default();
    results.add_human_warning("Runtime warning");
    results.add_human_warning("Runtime warning");

    let warnings = formatter.collect_human_warnings(&results);
    assert_eq!(
        warnings
            .iter()
            .filter(|warning| warning.as_str() == "Runtime warning")
            .count(),
        1
    );
}

#[test]
fn test_format_bool_indicator() {
    let yes_result = format_bool_indicator(true, "Yes", "No");
    assert!(yes_result.to_string().contains("Y Yes"));

    let no_result = format_bool_indicator(false, "Yes", "No");
    assert!(no_result.to_string().contains("X No"));
}

#[test]
fn test_truncate_with_ellipsis() {
    assert_eq!(truncate_with_ellipsis("short", 10), "short");
    assert_eq!(
        truncate_with_ellipsis("this is a long string", 10),
        "this is..."
    );
}

#[test]
fn test_truncate_with_ellipsis_exact_length() {
    assert_eq!(truncate_with_ellipsis("tenletters", 10), "tenletters");
}

#[test]
fn test_truncate_with_ellipsis_tiny_max_len() {
    // When max_len <= 3, we can't fit any chars + "...", so return original
    let truncated = truncate_with_ellipsis("longstring", 2);
    assert_eq!(truncated, "longstring");
    // When max_len > 3, truncation works
    let truncated = truncate_with_ellipsis("longstring", 6);
    assert_eq!(truncated, "lon...");
}

#[test]
fn test_format_timing() {
    assert_eq!(format_timing(false, Some(100)), "");
    let timing = format_timing(true, Some(100));
    assert!(timing.contains("100"));
    assert_eq!(format_timing(true, None), "");
}

#[test]
fn test_format_status_indicator() {
    let yes = format_status_indicator(true);
    assert!(yes.to_string().contains("Y"));

    let no = format_status_indicator(false);
    assert!(no.to_string().contains("X"));
}

#[test]
fn test_format_threat_level_variants() {
    let critical = format_threat_level("critical");
    assert!(critical.to_string().contains("critical"));

    let low = format_threat_level("low");
    assert!(low.to_string().contains("low"));

    let unknown = format_threat_level("informational");
    assert!(unknown.to_string().contains("informational"));
}

#[test]
fn test_get_cert_type() {
    assert_eq!(get_cert_type(0, 3), "Leaf Certificate");
    assert_eq!(get_cert_type(1, 3), "Intermediate CA");
    assert_eq!(get_cert_type(2, 3), "Root/Top CA");
    assert_eq!(get_cert_type(1, 2), "Issuer CA");
}

#[test]
fn test_more_format_helpers() {
    let status_yes = format_status_indicator(true);
    let status_no = format_status_indicator(false);
    assert!(status_yes.to_string().contains("Y"));
    assert!(status_no.to_string().contains("X"));

    assert_eq!(format_avg_timing(false, Some(10)), "");
    let avg = format_avg_timing(true, Some(10));
    assert!(avg.contains("avg"));
}

#[test]
fn test_grade_and_threat_helpers() {
    let grade_a = format_ssl_grade(&crate::rating::Grade::A);
    let grade_f = format_ssl_grade(&crate::rating::Grade::F);
    assert!(grade_a.to_string().contains("Grade"));
    assert!(grade_f.to_string().contains("Grade"));

    let http_a = format_http_grade(&SecurityGrade::A);
    let http_f = format_http_grade(&SecurityGrade::F);
    assert!(http_a.to_string().contains("Grade"));
    assert!(http_f.to_string().contains("Grade"));

    let adv_a = format_advanced_grade(&HeaderGrade::A);
    let adv_f = format_advanced_grade(&HeaderGrade::F);
    assert!(adv_a.to_string().contains("Grade A"));
    assert!(adv_f.to_string().contains("Grade F"));

    let threat = format_threat_level("critical");
    assert!(threat.to_string().to_lowercase().contains("critical"));
    let threat_unknown = format_threat_level("unknown");
    assert!(
        threat_unknown
            .to_string()
            .to_lowercase()
            .contains("unknown")
    );
}

#[test]
fn test_advanced_grade_mid_range() {
    let grade_c = format_advanced_grade(&HeaderGrade::C);
    assert!(grade_c.to_string().contains("Grade C"));
}

#[test]
fn test_certificate_helpers() {
    let good_key = format_key_size(2048);
    let bad_key = format_key_size(1024);
    assert!(good_key.to_string().contains("2048"));
    assert!(bad_key.to_string().contains("1024"));

    let status = format_revocation_status(&RevocationStatus::Revoked);
    assert!(status.to_string().contains("REVOKED"));
}

#[test]
fn test_cipher_and_http_helpers() {
    let counts = CipherCounts {
        total: 5,
        null_ciphers: 1,
        export_ciphers: 1,
        low_strength: 1,
        medium_strength: 1,
        high_strength: 1,
        forward_secrecy: 2,
        aead: 3,
    };
    display_cipher_strength_distribution(&counts);
    display_cipher_security_features(&counts);

    let ok = format_http_status(200);
    let redirect = format_http_status(302);
    let err = format_http_status(404);
    assert!(ok.to_string().contains("200"));
    assert!(redirect.to_string().contains("302"));
    assert!(err.to_string().contains("404"));

    assert_eq!(format_http_issue_icon(&HeaderIssueType::Missing), "X");
    assert_eq!(format_http_issue_icon(&HeaderIssueType::Insecure), "!");
    assert_eq!(format_http_issue_icon(&HeaderIssueType::Deprecated), "i");
}

#[test]
fn test_client_sim_summary_helper() {
    let all_ok = format_client_sim_summary(2, 2);
    let none_ok = format_client_sim_summary(0, 2);
    let some_ok = format_client_sim_summary(1, 2);
    assert!(all_ok.to_string().contains("2/2"));
    assert!(none_ok.to_string().contains("0/2"));
    assert!(some_ok.to_string().contains("1/2"));
}

#[test]
fn test_intolerance_checks_display() {
    let mut details = HashMap::new();
    details.insert(
        "extension_intolerance".to_string(),
        "Extension intolerance".to_string(),
    );
    details.insert(
        "version_intolerance".to_string(),
        "Version intolerance".to_string(),
    );
    details.insert(
        "long_handshake_intolerance".to_string(),
        "Long handshake intolerance".to_string(),
    );
    details.insert(
        "incorrect_sni_alerts".to_string(),
        "Incorrect SNI alerts".to_string(),
    );
    details.insert(
        "uses_common_dh_primes".to_string(),
        "Common DH primes".to_string(),
    );

    let results = IntoleranceTestResult {
        extension_intolerance: true,
        version_intolerance: true,
        long_handshake_intolerance: true,
        incorrect_sni_alerts: true,
        uses_common_dh_primes: true,
        inconclusive: false,
        inconclusive_checks: Vec::new(),
        details,
    };

    for check in build_intolerance_checks(&results) {
        check.display(&results.details);
    }
}

#[test]
fn test_display_sections_smoke() {
    let args = Args {
        scan: crate::cli::ScanArgs {
            show_certificates: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let formatter = ScannerFormatter::new(&args);

    let leaf = CertificateInfo {
        subject: "CN=example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial_number: "01".to_string(),
        not_before: "2025-01-01".to_string(),
        not_after: "2026-01-01".to_string(),
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key_algorithm: "RSA".to_string(),
        public_key_size: Some(2048),
        rsa_exponent: Some("e 65537".to_string()),
        san: vec!["example.com".to_string()],
        debian_weak_key: Some(true),
        fingerprint_sha256: Some("AA:BB".to_string()),
        pin_sha256: Some("pin".to_string()),
        aia_url: Some("http://ca.example.com".to_string()),
        der_bytes: vec![0u8; 4],
        ..Default::default()
    };

    let root = CertificateInfo {
        subject: "CN=Root".to_string(),
        issuer: "CN=Root".to_string(),
        is_ca: true,
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key_algorithm: "RSA".to_string(),
        public_key_size: Some(4096),
        der_bytes: vec![0u8; 4],
        ..Default::default()
    };

    let chain = CertificateChain {
        certificates: vec![leaf.clone(), root],
        chain_length: 2,
        chain_size_bytes: 8,
    };

    let mut platform_status = HashMap::new();
    platform_status.insert(
        TrustStore::Mozilla,
        PlatformTrustStatus {
            platform: TrustStore::Mozilla,
            trusted: true,
            trusted_root: Some("Mozilla Root".to_string()),
            message: "Trusted".to_string(),
            details: ValidationDetails {
                chain_verified: true,
                root_in_store: true,
                signatures_valid: true,
                trust_anchor: Some("Mozilla Root".to_string()),
            },
        },
    );
    platform_status.insert(
        TrustStore::Windows,
        PlatformTrustStatus {
            platform: TrustStore::Windows,
            trusted: false,
            trusted_root: None,
            message: "Untrusted".to_string(),
            details: ValidationDetails {
                chain_verified: false,
                root_in_store: false,
                signatures_valid: false,
                trust_anchor: None,
            },
        },
    );

    let platform_trust = TrustValidationResult {
        platform_status,
        overall_trusted: true,
        trusted_count: 1,
        total_platforms: 2,
    };

    let validation = ValidationResult {
        valid: false,
        issues: vec![ValidationIssue {
            severity: IssueSeverity::High,
            issue_type: IssueType::HostnameMismatch,
            description: "Hostname mismatch".to_string(),
        }],
        trust_chain_valid: false,
        hostname_match: false,
        not_expired: true,
        signature_valid: true,
        trusted_ca: Some("Test CA".to_string()),
        platform_trust: Some(platform_trust),
    };

    let revocation = RevocationResult {
        status: RevocationStatus::Revoked,
        method: RevocationMethod::OCSP,
        details: "Revoked".to_string(),
        ocsp_stapling: true,
        ocsp_stapling_details: None,
        must_staple: false,
    };

    let cert_result = crate::scanner::CertificateAnalysisResult {
        chain,
        validation,
        revocation: Some(revocation),
    };
    formatter.display_certificate_results(&cert_result);

    let protocol_results = vec![
        ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            inconclusive: false,
            preferred: true,
            ciphers_count: 3,
            handshake_time_ms: Some(12),
            heartbeat_enabled: Some(true),
            session_resumption_caching: Some(false),
            session_resumption_tickets: Some(true),
            secure_renegotiation: Some(true),
        },
        ProtocolTestResult {
            protocol: Protocol::SSLv3,
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
    formatter.display_protocol_results(&protocol_results);

    let cipher = CipherSuite {
        hexcode: "0x1301".to_string(),
        openssl_name: "TLS_AES_128_GCM_SHA256".to_string(),
        iana_name: "TLS_AES_128_GCM_SHA256".to_string(),
        protocol: "TLSv1.3".to_string(),
        key_exchange: "ECDHE".to_string(),
        authentication: "RSA".to_string(),
        encryption: "AES_128_GCM".to_string(),
        mac: "AEAD".to_string(),
        bits: 128,
        export: false,
    };
    let summary = ProtocolCipherSummary {
        protocol: Protocol::TLS12,
        supported_ciphers: vec![cipher.clone()],
        server_ordered: true,
        server_preference: vec!["0x1301".to_string()],
        preferred_cipher: Some(cipher),
        counts: CipherCounts {
            total: 1,
            null_ciphers: 0,
            export_ciphers: 0,
            low_strength: 0,
            medium_strength: 0,
            high_strength: 1,
            forward_secrecy: 1,
            aead: 1,
        },
        avg_handshake_time_ms: Some(8),
    };
    let mut cipher_map = HashMap::new();
    cipher_map.insert(Protocol::TLS12, summary);
    formatter.display_cipher_results(&cipher_map);

    let alpn_report = AlpnReport {
        alpn_enabled: true,
        alpn_result: AlpnResult {
            supported_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            http2_supported: true,
            http3_supported: false,
            negotiated_protocol: Some("h2".to_string()),
            details: vec!["ALPN ok".to_string()],
            inconclusive: false,
        },
        spdy_supported: false,
        recommendations: vec!["Enable HTTP/3".to_string()],
        inconclusive: false,
    };
    formatter.display_alpn_results(&alpn_report);

    let mut headers = HashMap::new();
    headers.insert(
        "strict-transport-security".to_string(),
        "max-age=63072000; includeSubDomains; preload".to_string(),
    );
    let header_result = HeaderAnalysisResult {
        headers,
        issues: vec![HeaderIssue {
            header_name: "Content-Security-Policy".to_string(),
            severity: HeaderSeverity::High,
            issue_type: HeaderIssueType::Missing,
            description: "CSP missing".to_string(),
            recommendation: "Add CSP".to_string(),
            preload_status: None,
        }],
        score: 75,
        grade: SecurityGrade::B,
        hsts_analysis: Some(HstsAnalysis {
            enabled: true,
            max_age: Some(63_072_000),
            include_subdomains: true,
            preload: true,
            details: "Strong policy".to_string(),
            grade: HeaderGrade::A,
        }),
        hpkp_analysis: Some(HpkpAnalysis {
            enabled: true,
            max_age: Some(1000),
            include_subdomains: false,
            report_uri: None,
            pins: vec!["pin1".to_string()],
            backup_pins: vec!["pin2".to_string()],
            details: "HPKP enabled".to_string(),
        }),
        cookie_analysis: Some(CookieAnalysis {
            cookies: vec![CookieInfo {
                name: "session".to_string(),
                secure: true,
                httponly: true,
                samesite: Some("Lax".to_string()),
                domain: Some("example.com".to_string()),
                path: Some("/".to_string()),
                expires: None,
            }],
            secure_count: 1,
            httponly_count: 1,
            samesite_count: 1,
            insecure_count: 0,
            details: "Cookies are secure".to_string(),
            grade: HeaderGrade::A,
        }),
        datetime_check: Some(DateTimeCheck {
            server_date: Some("Tue, 01 Jan 2026 00:00:00 GMT".to_string()),
            skew_seconds: Some(5),
            synchronized: true,
            details: "Clock OK".to_string(),
        }),
        banner_detection: Some(BannerDetection {
            server: Some("nginx".to_string()),
            powered_by: Some("Rust".to_string()),
            application: Some("CipherRun".to_string()),
            framework: Some("axum".to_string()),
            version_exposed: true,
            details: "Version exposed".to_string(),
            grade: HeaderGrade::C,
        }),
        reverse_proxy_detection: Some(ReverseProxyDetection {
            detected: true,
            via_header: Some("1.1 proxy".to_string()),
            x_forwarded_for: true,
            x_real_ip: false,
            x_forwarded_proto: true,
            proxy_type: Some("CDN".to_string()),
            details: "Proxy detected".to_string(),
        }),
        http_status_code: Some(302),
        redirect_location: Some("https://example.com".to_string()),
        redirect_chain: vec!["https://example.com".to_string()],
        server_hostname: Some("example.com".to_string()),
    };
    formatter.display_http_headers_results(&header_result);

    let vulnerabilities = vec![
        VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: false,
            inconclusive: false,
            details: "Safe".to_string(),
            cve: Some("CVE-2014-0160".to_string()),
            cwe: None,
            severity: Severity::Low,
        },
        VulnerabilityResult {
            vuln_type: VulnerabilityType::POODLE,
            vulnerable: true,
            inconclusive: false,
            details: "Vulnerable".to_string(),
            cve: Some("CVE-2014-3566".to_string()),
            cwe: None,
            severity: Severity::High,
        },
    ];
    formatter.display_vulnerability_results(&vulnerabilities);

    let rating = RatingResult {
        grade: crate::rating::Grade::B,
        score: 80,
        certificate_score: 90,
        protocol_score: 85,
        key_exchange_score: 78,
        cipher_strength_score: 82,
        warnings: vec!["Warn".to_string()],
    };
    formatter.display_rating_results(&rating);

    let clients = vec![
        ClientSimulationResult {
            client_name: "Firefox".to_string(),
            client_id: "fx".to_string(),
            success: true,
            protocol: Some(Protocol::TLS13),
            cipher: Some("TLS_AES_128_GCM_SHA256".to_string()),
            error: None,
            handshake_time_ms: Some(12),
            alpn: Some("h2".to_string()),
            key_exchange: Some("ECDHE".to_string()),
            forward_secrecy: true,
            certificate_type: Some("RSA 2048".to_string()),
        },
        ClientSimulationResult {
            client_name: "OldBrowser".to_string(),
            client_id: "old".to_string(),
            success: false,
            protocol: None,
            cipher: None,
            error: Some("Handshake failed".to_string()),
            handshake_time_ms: None,
            alpn: None,
            key_exchange: None,
            forward_secrecy: false,
            certificate_type: None,
        },
    ];
    formatter.display_client_simulation_results(&clients);

    let client_cas = ClientCAsResult {
        cas: vec![ClientCA {
            distinguished_name: "CN=Client CA".to_string(),
            organization: Some("Example Org".to_string()),
            common_name: Some("Client CA".to_string()),
        }],
        requires_client_auth: true,
        inconclusive: false,
    };
    formatter.display_client_cas_results(&client_cas);
}

#[test]
fn test_display_results_summary_and_headers() {
    let args = Args {
        output: crate::cli::OutputArgs {
            show_times: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let formatter = ScannerFormatter::new(&args);

    let protocol_results = vec![ProtocolTestResult {
        protocol: Protocol::TLS13,
        supported: true,
        inconclusive: false,
        preferred: true,
        ciphers_count: 2,
        handshake_time_ms: Some(5),
        heartbeat_enabled: Some(false),
        session_resumption_caching: Some(true),
        session_resumption_tickets: Some(true),
        secure_renegotiation: Some(true),
    }];

    let mut headers = HashMap::new();
    headers.insert("server".to_string(), "nginx".to_string());
    let http_headers = HeaderAnalysisResult {
        headers,
        issues: Vec::new(),
        score: 100,
        grade: SecurityGrade::A,
        hsts_analysis: None,
        hpkp_analysis: None,
        cookie_analysis: None,
        datetime_check: None,
        banner_detection: None,
        reverse_proxy_detection: None,
        http_status_code: Some(200),
        redirect_location: None,
        redirect_chain: Vec::new(),
        server_hostname: Some("example.com".to_string()),
    };

    let rating = RatingResult {
        grade: crate::rating::Grade::A,
        score: 95,
        certificate_score: 98,
        protocol_score: 90,
        key_exchange_score: 92,
        cipher_strength_score: 94,
        warnings: Vec::new(),
    };

    let ja3 = Ja3Fingerprint {
        ja3_string: "771,4865,0-10,23,0".to_string(),
        ja3_hash: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ssl_version: 771,
        ciphers: vec![4865],
        extensions: vec![0, 10],
        curves: vec![23],
        point_formats: vec![0],
    };

    let ja3_sig = Ja3Signature {
        name: "TestClient".to_string(),
        category: "Browser".to_string(),
        description: "Test signature".to_string(),
        threat_level: "high".to_string(),
    };

    let results = crate::scanner::ScanResults {
        target: "example.com:443".to_string(),
        scan_time_ms: 123,
        protocols: protocol_results,
        http: Some(crate::scanner::HttpResults {
            http_headers: Some(http_headers),
        }),
        rating: Some(crate::scanner::RatingResults {
            ssl_rating: Some(rating),
        }),
        fingerprints: Some(crate::scanner::FingerprintResults {
            ja3_fingerprint: Some(ja3),
            ja3_match: Some(ja3_sig),
            ja3s_fingerprint: None,
            ja3s_match: None,
            jarm_fingerprint: None,
            client_hello_raw: None,
            server_hello_raw: None,
        }),
        ..Default::default()
    };

    formatter.display_results_summary(&results);
}

#[test]
fn test_misc_display_helpers_and_fingerprints() {
    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);

    formatter.print_scan_header("example.com", 443, Some("SMTP"));
    formatter.print_phase_progress("phase");
    formatter.print_phase_progress_nl("phase");
    formatter.print_error("error");

    let signature_result = SignatureEnumerationResult {
        algorithms: vec![
            SignatureAlgorithm {
                name: "rsa_pkcs1_sha256".to_string(),
                iana_value: 0x0401,
                supported: true,
            },
            SignatureAlgorithm {
                name: "ecdsa_secp256r1_sha256".to_string(),
                iana_value: 0x0403,
                supported: false,
            },
        ],
        inconclusive: false,
    };
    formatter.display_signature_results(&signature_result);

    let group_result = GroupEnumerationResult {
        groups: vec![
            KeyExchangeGroup {
                name: "secp256r1".to_string(),
                iana_value: 23,
                group_type: GroupType::EllipticCurve,
                bits: 256,
                supported: true,
                quantum_vulnerable: true,
            },
            KeyExchangeGroup {
                name: "ffdhe2048".to_string(),
                iana_value: 256,
                group_type: GroupType::FiniteField,
                bits: 2048,
                supported: false,
                quantum_vulnerable: true,
            },
        ],
        measured: true,
        details: "test fixture".to_string(),
    };
    formatter.display_group_results(&group_result);

    let ja3 = Ja3Fingerprint {
        ja3_string: "771,4865,0-10,23,0".to_string(),
        ja3_hash: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ssl_version: 771,
        ciphers: vec![4865],
        extensions: vec![0, 10],
        curves: vec![23],
        point_formats: vec![0],
    };
    let ja3_sig = Ja3Signature {
        name: "TestClient".to_string(),
        category: "Tool".to_string(),
        description: "Test signature".to_string(),
        threat_level: "low".to_string(),
    };
    formatter.display_ja3_results(&ja3, Some(&ja3_sig));

    let ja3s = Ja3sFingerprint {
        ja3s_string: "771,4865,0-10".to_string(),
        ja3s_hash: "abcabcabcabcabcabcabcabcabcabcab".to_string(),
        ssl_version: 771,
        cipher: 4865,
        extensions: vec![0, 10],
    };
    let ja3s_sig = Ja3sSignature {
        name: "TestServer".to_string(),
        server_type: ServerType::CDN,
        description: "Test JA3S".to_string(),
        common_ports: vec![443],
        indicators: vec!["cdn".to_string()],
    };
    formatter.display_ja3s_results(&ja3s, Some(&ja3s_sig));

    let jarm = JarmFingerprint {
        hash: "abc123".to_string(),
        raw_responses: vec!["resp1".to_string(), "resp2".to_string()],
        signature: Some(JarmSignature {
            hash: "abc123".to_string(),
            name: "TestJarm".to_string(),
            server_type: "server".to_string(),
            description: Some("desc".to_string()),
            threat_level: Some("low".to_string()),
        }),
    };
    formatter.display_jarm_results(&jarm);
}

#[test]
fn test_pqc_section_none_level_renders_without_panic() {
    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);
    let assessment = PqcReadinessAssessment {
        score: 0,
        level: PqcLevel::None,
        pq_safe_groups: vec![],
        quantum_vulnerable_only: true,
        hndl_risk: true,
        recommendations: vec!["Deploy X25519MLKEM768.".to_string()],
    };
    formatter.display_pqc_readiness_results(&assessment);
}

#[test]
fn test_pqc_section_full_level_renders_without_panic() {
    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);
    let assessment = PqcReadinessAssessment {
        score: 90,
        level: PqcLevel::Full,
        pq_safe_groups: vec!["X25519MLKEM768".to_string()],
        quantum_vulnerable_only: false,
        hndl_risk: false,
        recommendations: vec![],
    };
    formatter.display_pqc_readiness_results(&assessment);
}

#[test]
fn test_pqc_section_with_recommendations_renders_without_panic() {
    let args = Args::default();
    let formatter = ScannerFormatter::new(&args);
    let assessment = PqcReadinessAssessment {
        score: 30,
        level: PqcLevel::Partial,
        pq_safe_groups: vec![],
        quantum_vulnerable_only: true,
        hndl_risk: true,
        recommendations: vec![
            "Enable TLS 1.3.".to_string(),
            "Deploy X25519MLKEM768.".to_string(),
        ],
    };
    formatter.display_pqc_readiness_results(&assessment);
}
