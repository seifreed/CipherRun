// CipherRun - Conservative Aggregation for Multi-IP Scans
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

//! Conservative aggregation module for combining scan results from multiple IPs.
//!
//! This module implements a worst-case aggregation strategy:
//! - Protocols: Only marked as supported if ALL IPs support them
//! - Cipher suites: Union of all cipher suites across all IPs
//! - Grade: Takes the WORST (lowest) grade from all IPs
//! - Certificates: Most common certificate chain, or marks differences
//!
//! This conservative approach ensures that the aggregated result represents
//! the weakest security posture in a load-balanced environment.

mod certificate;
mod ciphers;
mod grade;
mod protocols;
mod session;

use crate::certificates::parser::{CertificateChain, CertificateInfo};
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::scanner::inconsistency::{Inconsistency, SingleIpScanResult};
use crate::scanner::results::serialize_sorted_map;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub(super) fn certificate_signature(cert: &CertificateInfo) -> String {
    if let Some(fingerprint) = cert.fingerprint_sha256.as_ref() {
        return format!("fp:{}", fingerprint);
    }

    if !cert.der_bytes.is_empty() {
        return format!("der:{}", hex::encode(&cert.der_bytes));
    }

    serde_json::to_string(cert).unwrap_or_else(|_| {
        format!(
            "subject={};issuer={};serial={};not_before={};not_after={}",
            cert.subject, cert.issuer, cert.serial_number, cert.not_before, cert.not_after
        )
    })
}

pub(super) fn certificate_chain_signature(chain: &CertificateChain) -> String {
    if chain.certificates.is_empty() {
        return "<empty>".to_string();
    }

    chain
        .certificates
        .iter()
        .map(certificate_signature)
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

/// Aggregated scan result representing the conservative view across all IPs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedScanResult {
    /// Protocol test results (only protocols supported by ALL IPs)
    pub protocols: Vec<ProtocolTestResult>,

    /// Cipher suites (union of all ciphers across all IPs)
    #[serde(serialize_with = "serialize_sorted_map")]
    pub ciphers: HashMap<Protocol, ProtocolCipherSummary>,

    /// Overall grade (WORST grade from all IPs)
    pub grade: (String, u8),

    /// Most common certificate chain (leaf returned, or indication of differences)
    pub certificate_info: Option<CertificateInfo>,
    pub certificate_consistent: bool,

    /// List of detected inconsistencies
    pub inconsistencies: Vec<Inconsistency>,

    /// ALPN protocols (intersection - only those supported by all)
    pub alpn_protocols: Vec<String>,

    /// Session resumption (conservative - Some(true) only if all measured backends support it)
    pub session_resumption_caching: Option<bool>,
    pub session_resumption_tickets: Option<bool>,
}

/// Conservative aggregator for multi-IP scan results
pub struct ConservativeAggregator {
    pub(super) results: HashMap<IpAddr, SingleIpScanResult>,
    pub(super) inconsistencies: Vec<Inconsistency>,
}

impl ConservativeAggregator {
    /// Create a new conservative aggregator
    pub fn new(
        results: HashMap<IpAddr, SingleIpScanResult>,
        inconsistencies: Vec<Inconsistency>,
    ) -> Self {
        Self {
            results,
            inconsistencies,
        }
    }

    /// Aggregate all results using conservative strategy
    pub fn aggregate(&self) -> AggregatedScanResult {
        AggregatedScanResult {
            protocols: self.aggregate_protocols_conservative(),
            ciphers: self.aggregate_ciphers_conservative(),
            grade: self.aggregate_grade_conservative(),
            certificate_info: self.aggregate_certificate(),
            certificate_consistent: self.check_certificate_consistency(),
            inconsistencies: self.inconsistencies.clone(),
            alpn_protocols: self.aggregate_alpn_conservative(),
            session_resumption_caching: self.aggregate_session_resumption_caching(),
            session_resumption_tickets: self.aggregate_session_resumption_tickets(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::parser::{CertificateChain, CertificateInfo};
    use crate::certificates::validator::ValidationResult;
    use crate::ciphers::CipherSuite;
    use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
    use crate::protocols::ProtocolTestResult;
    use crate::rating::grader::Grade;
    use crate::rating::scoring::RatingResult;
    use crate::scanner::{AdvancedResults, CertificateAnalysisResult, RatingResults, ScanResults};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_empty_aggregation() {
        let aggregator = ConservativeAggregator::new(HashMap::new(), Vec::new());
        let result = aggregator.aggregate();
        assert!(result.protocols.is_empty());
        assert_eq!(result.grade, ("F".to_string(), 0));
    }

    #[test]
    fn test_certificate_consistency_single_cert() {
        let aggregator = ConservativeAggregator::new(HashMap::new(), Vec::new());
        assert!(aggregator.check_certificate_consistency());
    }

    #[test]
    fn test_certificate_consistency_detects_different_full_chains_with_same_leaf() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let mut results = HashMap::new();
        results.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: ScanResults {
                    certificate_chain: Some(make_certificate_chain(&[
                        "leaf",
                        "intermediate-a",
                        "root",
                    ])),
                    ..Default::default()
                },
                scan_duration_ms: 10,
                error: None,
            },
        );
        results.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: ScanResults {
                    certificate_chain: Some(make_certificate_chain(&[
                        "leaf",
                        "intermediate-b",
                        "root",
                    ])),
                    ..Default::default()
                },
                scan_duration_ms: 12,
                error: None,
            },
        );

        let aggregator = ConservativeAggregator::new(results, vec![]);
        let aggregated = aggregator.aggregate();

        assert!(!aggregated.certificate_consistent);
        assert_eq!(
            aggregated
                .certificate_info
                .and_then(|cert| cert.fingerprint_sha256),
            Some("leaf".to_string())
        );
    }

    #[test]
    fn test_aggregate_grade_conservative_prefers_certificate_over_low_numeric_score() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let mut results = HashMap::new();
        results.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: make_scan_result(
                    Vec::new(),
                    HashMap::new(),
                    "fp1",
                    Grade::T,
                    95,
                    Vec::new(),
                ),
                scan_duration_ms: 10,
                error: None,
            },
        );
        results.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: make_scan_result(
                    Vec::new(),
                    HashMap::new(),
                    "fp2",
                    Grade::A,
                    10,
                    Vec::new(),
                ),
                scan_duration_ms: 12,
                error: None,
            },
        );

        let aggregator = ConservativeAggregator::new(results, vec![]);
        assert_eq!(
            aggregator.aggregate_grade_conservative(),
            ("T".to_string(), 95)
        );
    }

    #[test]
    fn test_certificate_consistency_is_false_when_some_successful_backends_lack_certificates() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let mut results = HashMap::new();
        results.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: ScanResults {
                    certificate_chain: Some(make_certificate("leaf-a")),
                    ..Default::default()
                },
                scan_duration_ms: 10,
                error: None,
            },
        );
        results.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: ScanResults::default(),
                scan_duration_ms: 12,
                error: None,
            },
        );

        let aggregator = ConservativeAggregator::new(results, vec![]);
        let aggregated = aggregator.aggregate();

        assert!(!aggregated.certificate_consistent);
    }

    pub(crate) fn make_cipher(
        openssl_name: &str,
        bits: u16,
        key_exchange: &str,
        encryption: &str,
    ) -> CipherSuite {
        CipherSuite {
            hexcode: "0001".to_string(),
            openssl_name: openssl_name.to_string(),
            iana_name: openssl_name.to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: key_exchange.to_string(),
            authentication: "RSA".to_string(),
            encryption: encryption.to_string(),
            mac: "SHA256".to_string(),
            bits,
            export: false,
        }
    }

    pub(crate) fn make_summary(
        protocol: Protocol,
        ciphers: Vec<CipherSuite>,
    ) -> ProtocolCipherSummary {
        ProtocolCipherSummary {
            protocol,
            supported_ciphers: ciphers,
            server_ordered: false,
            server_preference: Vec::new(),
            preferred_cipher: None,
            counts: CipherCounts::default(),
            avg_handshake_time_ms: None,
        }
    }

    pub(crate) fn make_certificate(fingerprint: &str) -> CertificateAnalysisResult {
        let cert = CertificateInfo {
            fingerprint_sha256: Some(fingerprint.to_string()),
            der_bytes: vec![0x01, 0x02],
            ..Default::default()
        };

        let chain = CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 2,
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

        CertificateAnalysisResult {
            chain,
            validation,
            revocation: None,
        }
    }

    pub(crate) fn make_certificate_chain(chain_fingerprints: &[&str]) -> CertificateAnalysisResult {
        let certificates: Vec<_> = chain_fingerprints
            .iter()
            .enumerate()
            .map(|(index, fingerprint)| {
                let subject = format!("CN={}", fingerprint);
                let issuer = if index + 1 == chain_fingerprints.len() {
                    subject.clone()
                } else {
                    format!("CN=issuer-{}", fingerprint)
                };

                CertificateInfo {
                    fingerprint_sha256: Some((*fingerprint).to_string()),
                    subject,
                    issuer,
                    is_ca: index > 0,
                    ..Default::default()
                }
            })
            .collect();

        let chain = CertificateChain {
            chain_length: certificates.len(),
            chain_size_bytes: certificates.len() * 2,
            certificates,
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

        CertificateAnalysisResult {
            chain,
            validation,
            revocation: None,
        }
    }

    pub(crate) fn make_scan_result(
        protocols: Vec<ProtocolTestResult>,
        ciphers: HashMap<Protocol, ProtocolCipherSummary>,
        fingerprint: &str,
        grade: Grade,
        score: u8,
        alpn_protocols: Vec<String>,
    ) -> ScanResults {
        ScanResults {
            target: "example.test:443".to_string(),
            protocols,
            ciphers,
            certificate_chain: Some(make_certificate(fingerprint)),
            rating: Some(RatingResults {
                ssl_rating: Some(RatingResult {
                    grade,
                    score,
                    certificate_score: score,
                    protocol_score: score,
                    key_exchange_score: score,
                    cipher_strength_score: score,
                    warnings: Vec::new(),
                }),
            }),
            advanced: Some(AdvancedResults {
                alpn_result: Some(crate::protocols::alpn::AlpnReport {
                    alpn_enabled: true,
                    alpn_result: crate::protocols::alpn::AlpnResult {
                        supported_protocols: alpn_protocols,
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
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_conservative_aggregation_merges_results() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let protocol_tls12 = ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 2,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(true),
            secure_renegotiation: None,
        };
        let protocol_tls13 = ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: false,
            ciphers_count: 1,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(true),
            secure_renegotiation: None,
        };

        let mut ciphers_ip1 = HashMap::new();
        ciphers_ip1.insert(
            Protocol::TLS12,
            make_summary(
                Protocol::TLS12,
                vec![make_cipher(
                    "ECDHE-ECDSA-AES256-GCM-SHA384",
                    256,
                    "ECDHE",
                    "AES-256-GCM",
                )],
            ),
        );
        let scan1 = make_scan_result(
            vec![protocol_tls12.clone(), protocol_tls13.clone()],
            ciphers_ip1,
            "fp1",
            Grade::A,
            90,
            vec!["h2".to_string(), "http/1.1".to_string()],
        );

        let mut ciphers_ip2 = HashMap::new();
        ciphers_ip2.insert(
            Protocol::TLS12,
            make_summary(
                Protocol::TLS12,
                vec![make_cipher("AES128-SHA", 128, "RSA", "AES-128-CBC")],
            ),
        );
        let protocol_tls12_ip2 = ProtocolTestResult {
            session_resumption_caching: Some(false),
            session_resumption_tickets: Some(false),
            ..protocol_tls12.clone()
        };
        let scan2 = make_scan_result(
            vec![protocol_tls12_ip2],
            ciphers_ip2,
            "fp2",
            Grade::B,
            80,
            vec!["http/1.1".to_string()],
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

        let aggregator = ConservativeAggregator::new(results, vec![]);
        let aggregated = aggregator.aggregate();

        let tls13 = aggregated
            .protocols
            .iter()
            .find(|p| p.protocol == Protocol::TLS13)
            .expect("TLS13 should be present");
        assert!(!tls13.supported);

        let tls12 = aggregated
            .protocols
            .iter()
            .find(|p| p.protocol == Protocol::TLS12)
            .expect("TLS12 should be present");
        assert!(tls12.supported);

        let summary = aggregated
            .ciphers
            .get(&Protocol::TLS12)
            .expect("TLS12 summary should exist");
        assert_eq!(summary.supported_ciphers.len(), 2);
        assert_eq!(summary.counts.total, 2);
        assert_eq!(summary.counts.forward_secrecy, 1);
        assert_eq!(summary.counts.aead, 1);
        assert_eq!(summary.counts.high_strength, 1);
        assert_eq!(summary.counts.medium_strength, 1);

        assert_eq!(aggregated.grade, ("B".to_string(), 80));
        assert!(aggregated.certificate_info.is_some());
        assert!(!aggregated.certificate_consistent);
        assert_eq!(aggregated.alpn_protocols, vec!["http/1.1".to_string()]);
        assert_eq!(aggregated.session_resumption_caching, Some(false));
        assert_eq!(aggregated.session_resumption_tickets, Some(false));
    }

    #[test]
    fn test_aggregate_ciphers_conservative_is_stable_and_conservative() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let cipher_a = make_cipher("AES128-SHA", 128, "RSA", "AES-128-CBC");
        let cipher_b = make_cipher("ECDHE-ECDSA-AES256-GCM-SHA384", 256, "ECDHE", "AES-256-GCM");

        let mut ciphers_ip1 = HashMap::new();
        let mut summary_ip1 = make_summary(Protocol::TLS12, vec![cipher_a.clone()]);
        summary_ip1.server_ordered = true;
        summary_ip1.server_preference = vec!["0x002F".to_string()];
        summary_ip1.preferred_cipher = Some(cipher_a.clone());
        summary_ip1.avg_handshake_time_ms = Some(10);
        ciphers_ip1.insert(Protocol::TLS12, summary_ip1);

        let mut ciphers_ip2 = HashMap::new();
        let mut summary_ip2 = make_summary(Protocol::TLS12, vec![cipher_b.clone()]);
        summary_ip2.server_ordered = false;
        summary_ip2.server_preference = vec!["0xC030".to_string()];
        summary_ip2.preferred_cipher = Some(cipher_b.clone());
        summary_ip2.avg_handshake_time_ms = Some(20);
        ciphers_ip2.insert(Protocol::TLS12, summary_ip2);

        let protocol = ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(10),
            heartbeat_enabled: Some(true),
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(true),
            secure_renegotiation: Some(true),
        };
        let protocol_ip2 = ProtocolTestResult {
            handshake_time_ms: Some(20),
            heartbeat_enabled: Some(true),
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(true),
            secure_renegotiation: Some(false),
            preferred: false,
            ..protocol.clone()
        };

        let scan_ip1 = make_scan_result(
            vec![protocol.clone()],
            ciphers_ip1,
            "fp1",
            Grade::A,
            90,
            vec!["h2".to_string()],
        );
        let scan_ip2 = make_scan_result(
            vec![protocol_ip2],
            ciphers_ip2,
            "fp2",
            Grade::A,
            90,
            vec!["h2".to_string()],
        );

        let mut results_a = HashMap::new();
        results_a.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: scan_ip1.clone(),
                scan_duration_ms: 100,
                error: None,
            },
        );
        results_a.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: scan_ip2.clone(),
                scan_duration_ms: 120,
                error: None,
            },
        );

        let mut results_b = HashMap::new();
        results_b.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: scan_ip2,
                scan_duration_ms: 120,
                error: None,
            },
        );
        results_b.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: scan_ip1,
                scan_duration_ms: 100,
                error: None,
            },
        );

        let aggregated_a = ConservativeAggregator::new(results_a, vec![]).aggregate();
        let aggregated_b = ConservativeAggregator::new(results_b, vec![]).aggregate();

        let summary_a = aggregated_a
            .ciphers
            .get(&Protocol::TLS12)
            .expect("TLS12 summary should exist");
        let summary_b = aggregated_b
            .ciphers
            .get(&Protocol::TLS12)
            .expect("TLS12 summary should exist");

        let names_a: Vec<_> = summary_a
            .supported_ciphers
            .iter()
            .map(|cipher| cipher.openssl_name.as_str())
            .collect();
        let names_b: Vec<_> = summary_b
            .supported_ciphers
            .iter()
            .map(|cipher| cipher.openssl_name.as_str())
            .collect();

        assert_eq!(names_a, names_b);
        assert_eq!(
            names_a,
            vec![
                cipher_a.openssl_name.as_str(),
                cipher_b.openssl_name.as_str()
            ]
        );
        assert!(!summary_a.server_ordered);
        assert!(summary_a.server_preference.is_empty());
        assert!(summary_a.preferred_cipher.is_none());
        assert_eq!(summary_a.avg_handshake_time_ms, Some(15));
        assert_eq!(summary_a.counts.total, 2);
        assert_eq!(summary_a.counts.forward_secrecy, 1);
        assert_eq!(summary_a.counts.aead, 1);
    }

    #[test]
    fn test_aggregate_protocols_conservative_uses_consensus_metadata() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let cipher_ip1 = make_cipher("TLS_AES_128_GCM_SHA256", 128, "ECDHE", "AES-128-GCM");
        let cipher_ip2 = make_cipher(
            "TLS_CHACHA20_POLY1305_SHA256",
            256,
            "ECDHE",
            "CHACHA20-POLY1305",
        );

        let mut ciphers_ip1 = HashMap::new();
        ciphers_ip1.insert(
            Protocol::TLS13,
            make_summary(Protocol::TLS13, vec![cipher_ip1.clone()]),
        );

        let mut ciphers_ip2 = HashMap::new();
        ciphers_ip2.insert(
            Protocol::TLS13,
            make_summary(Protocol::TLS13, vec![cipher_ip2.clone()]),
        );

        let protocol_ip1 = ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(10),
            heartbeat_enabled: Some(true),
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(true),
            secure_renegotiation: Some(true),
        };
        let protocol_ip2 = ProtocolTestResult {
            preferred: false,
            handshake_time_ms: Some(20),
            heartbeat_enabled: Some(true),
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(true),
            secure_renegotiation: Some(false),
            ..protocol_ip1.clone()
        };

        let scan_ip1 = make_scan_result(
            vec![protocol_ip1],
            ciphers_ip1,
            "fp1",
            Grade::A,
            90,
            vec!["h2".to_string()],
        );
        let scan_ip2 = make_scan_result(
            vec![protocol_ip2],
            ciphers_ip2,
            "fp2",
            Grade::A,
            90,
            vec!["h2".to_string()],
        );

        let mut results_a = HashMap::new();
        results_a.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: scan_ip1.clone(),
                scan_duration_ms: 100,
                error: None,
            },
        );
        results_a.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: scan_ip2.clone(),
                scan_duration_ms: 120,
                error: None,
            },
        );

        let mut results_b = HashMap::new();
        results_b.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: scan_ip2,
                scan_duration_ms: 120,
                error: None,
            },
        );
        results_b.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: scan_ip1,
                scan_duration_ms: 100,
                error: None,
            },
        );

        let aggregated_a = ConservativeAggregator::new(results_a, vec![]).aggregate();
        let aggregated_b = ConservativeAggregator::new(results_b, vec![]).aggregate();

        let tls13_a = aggregated_a
            .protocols
            .iter()
            .find(|p| p.protocol == Protocol::TLS13)
            .expect("TLS13 should be present");
        let tls13_b = aggregated_b
            .protocols
            .iter()
            .find(|p| p.protocol == Protocol::TLS13)
            .expect("TLS13 should be present");

        assert!(tls13_a.supported);
        assert!(tls13_b.supported);
        assert!(!tls13_a.preferred);
        assert!(!tls13_b.preferred);
        assert_eq!(tls13_a.ciphers_count, 2);
        assert_eq!(tls13_b.ciphers_count, 2);
        assert_eq!(tls13_a.handshake_time_ms, Some(20));
        assert_eq!(tls13_b.handshake_time_ms, Some(20));
        assert_eq!(tls13_a.heartbeat_enabled, Some(true));
        assert_eq!(tls13_b.heartbeat_enabled, Some(true));
        assert_eq!(tls13_a.session_resumption_caching, Some(true));
        assert_eq!(tls13_b.session_resumption_caching, Some(true));
        assert_eq!(tls13_a.session_resumption_tickets, Some(true));
        assert_eq!(tls13_b.session_resumption_tickets, Some(true));
        assert_eq!(tls13_a.secure_renegotiation, None);
        assert_eq!(tls13_b.secure_renegotiation, None);
    }

    #[test]
    fn test_aggregate_certificate_tie_break_is_deterministic() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let scan_a = make_scan_result(vec![], HashMap::new(), "bbbb", Grade::A, 90, Vec::new());
        let scan_b = make_scan_result(vec![], HashMap::new(), "aaaa", Grade::A, 90, Vec::new());

        let mut results_a = HashMap::new();
        results_a.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: scan_a.clone(),
                scan_duration_ms: 100,
                error: None,
            },
        );
        results_a.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: scan_b.clone(),
                scan_duration_ms: 120,
                error: None,
            },
        );

        let mut results_b = HashMap::new();
        results_b.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: scan_b,
                scan_duration_ms: 120,
                error: None,
            },
        );
        results_b.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: scan_a,
                scan_duration_ms: 100,
                error: None,
            },
        );

        let aggregated_a = ConservativeAggregator::new(results_a, vec![]).aggregate();
        let aggregated_b = ConservativeAggregator::new(results_b, vec![]).aggregate();

        let fingerprint_a = aggregated_a
            .certificate_info
            .as_ref()
            .and_then(|cert| cert.fingerprint_sha256.as_deref());
        let fingerprint_b = aggregated_b
            .certificate_info
            .as_ref()
            .and_then(|cert| cert.fingerprint_sha256.as_deref());

        assert_eq!(fingerprint_a, Some("aaaa"));
        assert_eq!(fingerprint_a, fingerprint_b);
        assert!(!aggregated_a.certificate_consistent);
        assert!(!aggregated_b.certificate_consistent);
    }

    #[test]
    fn test_aggregate_protocols_marks_unsupported_when_not_all_support() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let protocols_ip1 = vec![ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let protocols_ip2 = vec![ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: false,
            preferred: false,
            ciphers_count: 0,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let mut results = HashMap::new();
        results.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: make_scan_result(
                    protocols_ip1,
                    HashMap::new(),
                    "fp1",
                    Grade::A,
                    90,
                    Vec::new(),
                ),
                scan_duration_ms: 1,
                error: None,
            },
        );
        results.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: make_scan_result(
                    protocols_ip2,
                    HashMap::new(),
                    "fp1",
                    Grade::A,
                    90,
                    Vec::new(),
                ),
                scan_duration_ms: 1,
                error: None,
            },
        );

        let aggregator = ConservativeAggregator::new(results, Vec::new());
        let aggregated = aggregator.aggregate();

        let tls13 = aggregated
            .protocols
            .iter()
            .find(|p| p.protocol == Protocol::TLS13)
            .expect("TLS 1.3 entry should exist");
        assert!(!tls13.supported);
    }
}
