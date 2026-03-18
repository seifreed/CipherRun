// Scanner module - Main scanning engine

mod builders;
pub mod config;
pub mod mass;
mod orchestration;
pub mod probe_status;
pub mod results;
mod service;

// Multi-IP modules - Scanner is now Send-compatible, enabling parallel IP scanning
pub mod aggregation;
pub mod inconsistency;
pub mod multi_ip;

// Phase-based scan orchestration (extracted from God Method)
pub mod phases;

// Re-export domain-specific configuration objects
pub use crate::protocols::ProtocolTestResult;
pub use config::{CertificateConfig, CipherTestConfig, ProtocolTestConfig};
pub use probe_status::{ErrorType as ProbeErrorType, ProbeStatus};
pub use results::{
    AdvancedResults, CertificateAnalysisResult, FingerprintResults, HttpResults, RatingResults,
    ScanResults, SniMethod,
};
pub use service::Scanner;

// Re-export progress reporter types for dependency injection
pub use phases::{ScanProgressReporter, SilentProgressReporter, TerminalProgressReporter};

#[cfg(test)]
mod tests {
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
    fn test_aggregate_vulnerabilities_merges_by_type() {
        let mut results = HashMap::new();

        let mut scan_a = ScanResults::default();
        scan_a.vulnerabilities = vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: false,
            inconclusive: false,
            details: "Not vulnerable".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Info,
        }];

        let mut scan_b = ScanResults::default();
        scan_b.vulnerabilities = vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: true,
            inconclusive: false,
            details: "RC4 supported".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        }];

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
    fn test_select_common_certificate_chain_prefers_matching_fingerprint() {
        let mut results = HashMap::new();

        let mut leaf_a = CertificateInfo::default();
        leaf_a.fingerprint_sha256 = Some("AA".to_string());
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

        let mut leaf_b = CertificateInfo::default();
        leaf_b.fingerprint_sha256 = Some("BB".to_string());
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

        let mut scan_a = ScanResults::default();
        scan_a.certificate_chain = Some(chain_a);
        let mut scan_b = ScanResults::default();
        scan_b.certificate_chain = Some(chain_b.clone());

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
    fn test_select_common_certificate_chain_fallback_to_first_success() {
        let mut results = HashMap::new();

        let mut leaf = CertificateInfo::default();
        leaf.fingerprint_sha256 = Some("CC".to_string());
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

        let mut scan = ScanResults::default();
        scan.certificate_chain = Some(chain.clone());

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
        results.advanced_mut().key_exchange_groups = Some(
            crate::protocols::groups::GroupEnumerationResult {
                groups: vec![],
                measured: false,
                details: String::new(),
            },
        );
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
        let mut args = Args::default();
        args.target = Some("example.com".to_string());
        let scanner = Scanner::new(args.to_scan_request()).expect("test assertion should succeed");

        let mut leaf = CertificateInfo::default();
        leaf.fingerprint_sha256 = Some("AA".to_string());
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

        let mut scan_result = ScanResults::default();
        scan_result.certificate_chain = Some(chain);
        scan_result.protocols = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];
        scan_result.vulnerabilities = vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: true,
            inconclusive: false,
            details: "RC4 supported".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::High,
        }];

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
        assert_eq!(result.vulnerabilities.len(), 1);
        assert!(result.certificate_chain.is_some());
        assert!(result.rating.is_some());
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
}
