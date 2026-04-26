// CipherRun - Inconsistency Detection for Multi-IP Scans
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

//! Inconsistency detection module for identifying configuration differences
//! across multiple backend servers (load balancer scenarios).
//!
//! This module implements detection logic for identifying discrepancies in:
//! - Protocol support (TLS 1.3, TLS 1.2, etc.)
//! - Cipher suite availability
//! - Certificate configurations
//! - Security grades
//! - Session resumption capabilities
//! - ALPN protocol support

use crate::protocols::Protocol;
use crate::vulnerabilities::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Types of inconsistencies that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InconsistencyType {
    /// Different protocol support across backends
    ProtocolSupport,
    /// Different cipher suites available
    CipherSuites,
    /// Different TLS versions supported
    TlsVersions,
    /// Different certificates served
    Certificates,
    /// Different security grades
    SecurityGrade,
    /// Different session resumption support
    SessionResumption,
    /// Different ALPN protocol support
    Alpn,
}

impl std::fmt::Display for InconsistencyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InconsistencyType::ProtocolSupport => write!(f, "Protocol Support"),
            InconsistencyType::CipherSuites => write!(f, "Cipher Suites"),
            InconsistencyType::TlsVersions => write!(f, "TLS Versions"),
            InconsistencyType::Certificates => write!(f, "Certificates"),
            InconsistencyType::SecurityGrade => write!(f, "Security Grade"),
            InconsistencyType::SessionResumption => write!(f, "Session Resumption"),
            InconsistencyType::Alpn => write!(f, "ALPN Support"),
        }
    }
}

/// Details about specific inconsistencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InconsistencyDetails {
    /// Protocol support differences
    Protocols {
        protocol: Protocol,
        ips_with_support: Vec<IpAddr>,
        ips_without_support: Vec<IpAddr>,
    },
    /// Certificate chain differences
    Certificates {
        #[serde(serialize_with = "crate::scanner::results::serialize_sorted_map")]
        fingerprints: HashMap<IpAddr, String>,
    },
    /// Grade differences
    Grades {
        #[serde(serialize_with = "crate::scanner::results::serialize_sorted_map")]
        grades: HashMap<IpAddr, (String, u8)>,
    },
    /// Cipher suite differences
    CipherSuites {
        #[serde(serialize_with = "crate::scanner::results::serialize_sorted_map")]
        differences: HashMap<IpAddr, Vec<String>>,
    },
    /// Session resumption differences
    SessionResumption {
        ips_with_caching: Vec<IpAddr>,
        ips_with_tickets: Vec<IpAddr>,
        ips_without: Vec<IpAddr>,
    },
    /// ALPN protocol differences
    Alpn {
        #[serde(serialize_with = "crate::scanner::results::serialize_sorted_map")]
        protocols_by_ip: HashMap<IpAddr, Vec<String>>,
    },
}

/// Represents a detected inconsistency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inconsistency {
    pub inconsistency_type: InconsistencyType,
    pub severity: Severity,
    pub description: String,
    pub ips_affected: Vec<IpAddr>,
    pub details: InconsistencyDetails,
}

/// Result from a single IP scan
///
/// Contains the scan results and metadata for a single IP address.
/// The scan_result field always contains data (may be default/empty if scan failed).
/// Check the error field to determine if the scan was successful.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleIpScanResult {
    pub ip: IpAddr,
    pub scan_result: crate::scanner::ScanResults,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

impl SingleIpScanResult {
    /// Check if this scan was successful
    pub fn is_successful(&self) -> bool {
        self.error.is_none()
    }
}

fn sort_ips(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.sort();
    ips
}

fn sort_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

/// Detector for identifying inconsistencies across multiple IP scan results
pub struct InconsistencyDetector {
    results: HashMap<IpAddr, SingleIpScanResult>,
}

impl InconsistencyDetector {
    /// Create a new inconsistency detector
    pub fn new(results: HashMap<IpAddr, SingleIpScanResult>) -> Self {
        Self { results }
    }

    /// Detect all inconsistencies across scan results
    pub fn detect_all(&self) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();
        let successful_scan_count = self.successful_scan_count();

        // Only detect inconsistencies if we have multiple successful scans
        if successful_scan_count < 2 {
            return inconsistencies;
        }

        // Detect protocol inconsistencies
        inconsistencies.extend(self.detect_protocol_inconsistencies());

        // Detect certificate inconsistencies
        inconsistencies.extend(self.detect_certificate_inconsistencies());

        // Detect cipher suite inconsistencies
        inconsistencies.extend(self.detect_cipher_inconsistencies());

        // Detect grade inconsistencies
        inconsistencies.extend(self.detect_grade_inconsistencies());

        // Detect session resumption inconsistencies
        inconsistencies.extend(self.detect_session_resumption_inconsistencies());

        // Detect ALPN inconsistencies
        inconsistencies.extend(self.detect_alpn_inconsistencies());

        inconsistencies
    }

    fn successful_scan_count(&self) -> usize {
        self.results
            .values()
            .filter(|result| result.error.is_none())
            .count()
    }

    /// Detect protocol support inconsistencies
    fn detect_protocol_inconsistencies(&self) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();

        // Check each protocol
        for protocol in Protocol::all() {
            let mut ips_with = Vec::new();
            let mut ips_without = Vec::new();

            for (ip, result) in &self.results {
                // Skip failed scans
                if result.error.is_some() {
                    continue;
                }

                // Check if this IP supports the protocol
                let supports = result
                    .scan_result
                    .protocols
                    .iter()
                    .any(|p| p.protocol == protocol && p.supported);

                if supports {
                    ips_with.push(*ip);
                } else {
                    ips_without.push(*ip);
                }
            }

            // If there's a discrepancy, it's an inconsistency
            if !ips_with.is_empty() && !ips_without.is_empty() {
                let ips_with = sort_ips(ips_with);
                let ips_without = sort_ips(ips_without);
                let severity = match protocol {
                    Protocol::TLS13 => Severity::High,
                    Protocol::TLS12 => Severity::Medium,
                    _ => Severity::Low,
                };

                inconsistencies.push(Inconsistency {
                    inconsistency_type: InconsistencyType::ProtocolSupport,
                    severity,
                    description: format!(
                        "{} support is inconsistent across backends ({}/{} IPs support it)",
                        protocol.name(),
                        ips_with.len(),
                        self.successful_scan_count()
                    ),
                    ips_affected: sort_ips(
                        ips_with.iter().chain(ips_without.iter()).copied().collect(),
                    ),
                    details: InconsistencyDetails::Protocols {
                        protocol,
                        ips_with_support: ips_with,
                        ips_without_support: ips_without,
                    },
                });
            }
        }

        inconsistencies
    }

    /// Detect certificate inconsistencies
    fn detect_certificate_inconsistencies(&self) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();
        let mut fingerprints: HashMap<IpAddr, String> = HashMap::new();
        let mut ips_without_cert: Vec<IpAddr> = Vec::new();

        // Collect certificate chain signatures so that intermediate differences
        // and chain length differences are not collapsed into leaf-only matches.
        for (ip, result) in &self.results {
            if result.error.is_some() {
                continue;
            }

            if let Some(ref cert_chain) = result.scan_result.certificate_chain {
                fingerprints.insert(
                    *ip,
                    super::aggregation::certificate_chain_signature(&cert_chain.chain),
                );
            } else {
                ips_without_cert.push(*ip);
            }
        }

        // Report inconsistency if some IPs have certs and others don't,
        // or if the certificate chains differ across IPs.
        // Both conditions are checked independently because a scenario like
        // "IP1 has cert A, IP2 has cert B, IP3 has no cert" should report
        // BOTH the "missing on some IPs" and "different chains" inconsistencies.
        if !ips_without_cert.is_empty() && !fingerprints.is_empty() {
            // Some IPs have certificates and others don't
            let mut all_ips: Vec<IpAddr> = fingerprints
                .keys()
                .copied()
                .chain(ips_without_cert.iter().copied())
                .collect();
            all_ips.sort();
            all_ips.dedup();
            inconsistencies.push(Inconsistency {
                inconsistency_type: InconsistencyType::Certificates,
                severity: Severity::High,
                description: format!(
                    "Certificate chain present on {} backends but missing on {} backends",
                    fingerprints.len(),
                    ips_without_cert.len()
                ),
                ips_affected: all_ips,
                details: InconsistencyDetails::Certificates {
                    fingerprints: fingerprints.clone(),
                },
            });
        }

        if fingerprints.len() > 1 {
            let unique_signatures: std::collections::HashSet<_> = fingerprints.values().collect();

            if unique_signatures.len() > 1 {
                inconsistencies.push(Inconsistency {
                    inconsistency_type: InconsistencyType::Certificates,
                    severity: Severity::High,
                    description: format!(
                        "Different certificate chains detected across {} backends ({} unique chains)",
                        fingerprints.len(),
                        unique_signatures.len()
                    ),
                    ips_affected: sort_ips(fingerprints.keys().copied().collect()),
                    details: InconsistencyDetails::Certificates { fingerprints },
                });
            }
        }

        inconsistencies
    }

    /// Detect cipher suite inconsistencies
    fn detect_cipher_inconsistencies(&self) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();
        let mut cipher_sets: HashMap<IpAddr, Vec<String>> = HashMap::new();

        // Collect cipher suites for each IP
        for (ip, result) in &self.results {
            if result.error.is_some() {
                continue;
            }

            let mut all_ciphers = Vec::new();
            for summary in result.scan_result.ciphers.values() {
                for cipher in &summary.supported_ciphers {
                    all_ciphers.push(cipher.openssl_name.clone());
                }
            }

            if !all_ciphers.is_empty() {
                all_ciphers = sort_strings(all_ciphers);
                cipher_sets.insert(*ip, all_ciphers);
            }
        }

        // Compare cipher sets
        if cipher_sets.len() > 1 {
            // Check if all sets are identical
            if let Some(first_ciphers) = cipher_sets.values().next() {
                let first_set: std::collections::HashSet<_> = first_ciphers.iter().collect();

                let all_identical = cipher_sets.values().all(|set| {
                    let current_set: std::collections::HashSet<_> = set.iter().collect();
                    current_set == first_set
                });

                if !all_identical {
                    inconsistencies.push(Inconsistency {
                        inconsistency_type: InconsistencyType::CipherSuites,
                        severity: Severity::Medium,
                        description: format!(
                            "Different cipher suites available across {} backends",
                            cipher_sets.len()
                        ),
                        ips_affected: sort_ips(cipher_sets.keys().copied().collect()),
                        details: InconsistencyDetails::CipherSuites {
                            differences: cipher_sets,
                        },
                    });
                }
            }
        }

        inconsistencies
    }

    /// Detect security grade inconsistencies
    fn detect_grade_inconsistencies(&self) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();
        let mut grades: HashMap<IpAddr, (String, u8)> = HashMap::new();

        // Collect grades
        for (ip, result) in &self.results {
            if result.error.is_some() {
                continue;
            }

            if let Some(rating) = result.scan_result.ssl_rating() {
                grades.insert(*ip, (format!("{}", rating.grade), rating.score));
            }
        }

        // Check if all grades are the same
        if grades.len() > 1 {
            let unique_grades: std::collections::HashSet<_> = grades.values().collect();

            if unique_grades.len() > 1 {
                inconsistencies.push(Inconsistency {
                    inconsistency_type: InconsistencyType::SecurityGrade,
                    severity: Severity::High,
                    description: format!(
                        "Different security grades across {} backends",
                        grades.len()
                    ),
                    ips_affected: sort_ips(grades.keys().copied().collect()),
                    details: InconsistencyDetails::Grades { grades },
                });
            }
        }

        inconsistencies
    }

    /// Detect session resumption inconsistencies
    fn detect_session_resumption_inconsistencies(&self) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();
        let mut ips_with_caching = Vec::new();
        let mut ips_with_tickets = Vec::new();
        let mut ips_without = Vec::new();

        for (ip, result) in &self.results {
            if result.error.is_some() {
                continue;
            }

            let mut has_caching = false;
            let mut has_tickets = false;

            for protocol_result in &result.scan_result.protocols {
                if protocol_result.supported {
                    if protocol_result.session_resumption_caching == Some(true) {
                        has_caching = true;
                    }
                    if protocol_result.session_resumption_tickets == Some(true) {
                        has_tickets = true;
                    }
                }
            }

            if has_caching {
                ips_with_caching.push(*ip);
            }
            if has_tickets {
                ips_with_tickets.push(*ip);
            }
            if !has_caching && !has_tickets {
                ips_without.push(*ip);
            }
        }

        // Detect inconsistencies in session resumption support:
        // 1. Some IPs have no resumption while others have some (original check)
        // 2. Some IPs with caching don't have tickets (tickets is a subset of caching)
        // 3. Some IPs have tickets but not caching (caching is a subset of all successful IPs)
        let total_successful = self.results.values().filter(|r| r.error.is_none()).count();

        let has_ips_without = !ips_without.is_empty()
            && (!ips_with_caching.is_empty() || !ips_with_tickets.is_empty());

        // Compare against total_successful (not ips_with_caching.len()) because a server
        // can support tickets without session-cache resumption — the two sets are independent.
        let tickets_inconsistent =
            !ips_with_tickets.is_empty() && ips_with_tickets.len() < total_successful;

        let caching_inconsistent =
            !ips_with_caching.is_empty() && ips_with_caching.len() < total_successful;

        if has_ips_without || tickets_inconsistent || caching_inconsistent {
            let ips_with_caching = sort_ips(ips_with_caching);
            let ips_with_tickets = sort_ips(ips_with_tickets);
            let ips_without = sort_ips(ips_without);

            let description = if has_ips_without {
                "Session resumption support inconsistent across backends"
            } else if tickets_inconsistent {
                "Session resumption ticket support inconsistent across backends"
            } else {
                "Session resumption caching support inconsistent across backends"
            };

            inconsistencies.push(Inconsistency {
                inconsistency_type: InconsistencyType::SessionResumption,
                severity: Severity::Medium,
                description: description.to_string(),
                ips_affected: {
                    let mut affected: Vec<IpAddr> = ips_with_caching
                        .iter()
                        .chain(ips_with_tickets.iter())
                        .chain(ips_without.iter())
                        .copied()
                        .collect();
                    affected.sort();
                    affected.dedup();
                    affected
                },
                details: InconsistencyDetails::SessionResumption {
                    ips_with_caching,
                    ips_with_tickets,
                    ips_without,
                },
            });
        }

        inconsistencies
    }

    /// Detect ALPN protocol inconsistencies
    fn detect_alpn_inconsistencies(&self) -> Vec<Inconsistency> {
        let mut inconsistencies = Vec::new();
        let mut protocols_by_ip: HashMap<IpAddr, Vec<String>> = HashMap::new();

        // Collect ALPN protocols for each IP
        for (ip, result) in &self.results {
            if result.error.is_some() {
                continue;
            }

            if let Some(alpn_report) = result.scan_result.alpn_result()
                && alpn_report.alpn_enabled
                && !alpn_report.alpn_result.supported_protocols.is_empty()
            {
                protocols_by_ip.insert(
                    *ip,
                    sort_strings(alpn_report.alpn_result.supported_protocols.clone()),
                );
            }
        }

        // Check if all IPs have ALPN enabled
        let ips_with_alpn: Vec<IpAddr> = sort_ips(protocols_by_ip.keys().copied().collect());
        let total_successful_ips = self.results.values().filter(|r| r.error.is_none()).count();

        // Detect inconsistency if some IPs have ALPN and others don't
        if !ips_with_alpn.is_empty() && ips_with_alpn.len() < total_successful_ips {
            let ips_without_alpn: Vec<IpAddr> = self
                .results
                .iter()
                .filter(|(ip, r)| r.error.is_none() && !protocols_by_ip.contains_key(ip))
                .map(|(ip, _)| *ip)
                .collect();
            let ips_without_alpn = sort_ips(ips_without_alpn);

            inconsistencies.push(Inconsistency {
                inconsistency_type: InconsistencyType::Alpn,
                severity: Severity::Medium,
                description: format!(
                    "ALPN support is inconsistent across backends ({}/{} IPs have ALPN enabled)",
                    ips_with_alpn.len(),
                    total_successful_ips
                ),
                ips_affected: sort_ips(
                    ips_with_alpn
                        .iter()
                        .chain(ips_without_alpn.iter())
                        .copied()
                        .collect(),
                ),
                details: InconsistencyDetails::Alpn {
                    protocols_by_ip: protocols_by_ip.clone(),
                },
            });
        }

        // If we have at least 2 IPs with ALPN, check for protocol differences
        if protocols_by_ip.len() > 1 {
            // Check if all protocol lists are identical
            if let Some(first_protocols_vec) = protocols_by_ip.values().next() {
                let first_protocols: std::collections::HashSet<_> =
                    first_protocols_vec.iter().collect();

                let all_identical = protocols_by_ip.values().all(|protocols| {
                    let current_set: std::collections::HashSet<_> = protocols.iter().collect();
                    current_set == first_protocols
                });

                if !all_identical {
                    inconsistencies.push(Inconsistency {
                        inconsistency_type: InconsistencyType::Alpn,
                        severity: Severity::Medium,
                        description: format!(
                            "Different ALPN protocols available across {} backends",
                            protocols_by_ip.len()
                        ),
                        ips_affected: sort_ips(protocols_by_ip.keys().copied().collect()),
                        details: InconsistencyDetails::Alpn { protocols_by_ip },
                    });
                }
            }
        }

        inconsistencies
    }
}

#[cfg(test)]
mod tests {
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
}
