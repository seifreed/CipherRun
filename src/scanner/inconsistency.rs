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
    /// Certificate fingerprint differences
    Certificates {
        fingerprints: HashMap<IpAddr, String>,
    },
    /// Grade differences
    Grades {
        grades: HashMap<IpAddr, (String, u8)>,
    },
    /// Cipher suite differences
    CipherSuites {
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

        // Only detect inconsistencies if we have multiple successful scans
        if self.results.len() < 2 {
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
                        self.results.len()
                    ),
                    ips_affected: ips_with.iter().chain(ips_without.iter()).copied().collect(),
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

        // Collect certificate fingerprints
        for (ip, result) in &self.results {
            if result.error.is_some() {
                continue;
            }

            if let Some(ref cert_chain) = result.scan_result.certificate_chain
                && let Some(cert) = cert_chain.chain.leaf()
                && let Some(ref fingerprint) = cert.fingerprint_sha256
            {
                fingerprints.insert(*ip, fingerprint.clone());
            }
        }

        // Check if all fingerprints are the same
        if fingerprints.len() > 1 {
            let unique_fingerprints: std::collections::HashSet<_> = fingerprints.values().collect();

            if unique_fingerprints.len() > 1 {
                inconsistencies.push(Inconsistency {
                    inconsistency_type: InconsistencyType::Certificates,
                    severity: Severity::High,
                    description: format!(
                        "Different certificates detected across {} backends ({} unique certificates)",
                        fingerprints.len(),
                        unique_fingerprints.len()
                    ),
                    ips_affected: fingerprints.keys().copied().collect(),
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
                        ips_affected: cipher_sets.keys().copied().collect(),
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
                    ips_affected: grades.keys().copied().collect(),
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

        // Detect inconsistencies in session resumption support
        if !ips_without.is_empty() && (!ips_with_caching.is_empty() || !ips_with_tickets.is_empty())
        {
            inconsistencies.push(Inconsistency {
                inconsistency_type: InconsistencyType::SessionResumption,
                severity: Severity::Medium,
                description: "Session resumption support inconsistent across backends".to_string(),
                ips_affected: ips_with_caching
                    .iter()
                    .chain(ips_with_tickets.iter())
                    .chain(ips_without.iter())
                    .copied()
                    .collect(),
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
                protocols_by_ip.insert(*ip, alpn_report.alpn_result.supported_protocols.clone());
            }
        }

        // Check if all IPs have ALPN enabled
        let ips_with_alpn: Vec<IpAddr> = protocols_by_ip.keys().copied().collect();
        let total_successful_ips = self.results.values().filter(|r| r.error.is_none()).count();

        // Detect inconsistency if some IPs have ALPN and others don't
        if !ips_with_alpn.is_empty() && ips_with_alpn.len() < total_successful_ips {
            let ips_without_alpn: Vec<IpAddr> = self
                .results
                .iter()
                .filter(|(ip, r)| r.error.is_none() && !protocols_by_ip.contains_key(ip))
                .map(|(ip, _)| *ip)
                .collect();

            inconsistencies.push(Inconsistency {
                inconsistency_type: InconsistencyType::Alpn,
                severity: Severity::Medium,
                description: format!(
                    "ALPN support is inconsistent across backends ({}/{} IPs have ALPN enabled)",
                    ips_with_alpn.len(),
                    total_successful_ips
                ),
                ips_affected: ips_with_alpn
                    .iter()
                    .chain(ips_without_alpn.iter())
                    .copied()
                    .collect(),
                details: InconsistencyDetails::Alpn {
                    protocols_by_ip: protocols_by_ip.clone(),
                },
            });
            return inconsistencies;
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
                        ips_affected: protocols_by_ip.keys().copied().collect(),
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
    use crate::scanner::ScanResults;

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
}
