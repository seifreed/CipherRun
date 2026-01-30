// CipherRun - Conservative Aggregation for Multi-IP Scans
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

//! Conservative aggregation module for combining scan results from multiple IPs.
//!
//! This module implements a worst-case aggregation strategy:
//! - Protocols: Only marked as supported if ALL IPs support them
//! - Cipher suites: Union of all cipher suites across all IPs
//! - Grade: Takes the WORST (lowest) grade from all IPs
//! - Certificates: Most common certificate, or marks differences
//!
//! This conservative approach ensures that the aggregated result represents
//! the weakest security posture in a load-balanced environment.

use crate::certificates::parser::CertificateInfo;
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::scanner::inconsistency::{Inconsistency, SingleIpScanResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Aggregated scan result representing the conservative view across all IPs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedScanResult {
    /// Protocol test results (only protocols supported by ALL IPs)
    pub protocols: Vec<ProtocolTestResult>,

    /// Cipher suites (union of all ciphers across all IPs)
    pub ciphers: HashMap<Protocol, ProtocolCipherSummary>,

    /// Overall grade (WORST grade from all IPs)
    pub grade: (String, u8),

    /// Most common certificate (or indication of differences)
    pub certificate_info: Option<CertificateInfo>,
    pub certificate_consistent: bool,

    /// List of detected inconsistencies
    pub inconsistencies: Vec<Inconsistency>,

    /// ALPN protocols (intersection - only those supported by all)
    pub alpn_protocols: Vec<String>,

    /// Session resumption (conservative - only if all support it)
    pub session_resumption_caching: bool,
    pub session_resumption_tickets: bool,
}

/// Conservative aggregator for multi-IP scan results
pub struct ConservativeAggregator {
    results: HashMap<IpAddr, SingleIpScanResult>,
    inconsistencies: Vec<Inconsistency>,
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

    /// Aggregate protocols conservatively - only protocols supported by ALL IPs
    fn aggregate_protocols_conservative(&self) -> Vec<ProtocolTestResult> {
        let mut aggregated = Vec::new();

        // Get all successful results
        let successful_results: Vec<_> = self
            .results
            .values()
            .filter(|r| r.error.is_none())
            .collect();

        if successful_results.is_empty() {
            return aggregated;
        }

        // For each protocol, check if ALL IPs support it
        for protocol in Protocol::all() {
            let all_support = successful_results.iter().all(|result| {
                result
                    .scan_result
                    .protocols
                    .iter()
                    .any(|p| p.protocol == protocol && p.supported)
            });

            // Take the best protocol test result details if supported by all
            if all_support {
                // Find the first result for this protocol to use as template
                if let Some(first_result) = successful_results.first()
                    && let Some(protocol_result) = first_result
                        .scan_result
                        .protocols
                        .iter()
                        .find(|p| p.protocol == protocol)
                {
                    aggregated.push(protocol_result.clone());
                }
            } else {
                // Add as unsupported
                aggregated.push(ProtocolTestResult {
                    protocol,
                    supported: false,
                    preferred: false,
                    ciphers_count: 0,
                    handshake_time_ms: None,
                    heartbeat_enabled: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                });
            }
        }

        aggregated
    }

    /// Aggregate cipher suites conservatively - union of all ciphers
    fn aggregate_ciphers_conservative(&self) -> HashMap<Protocol, ProtocolCipherSummary> {
        let mut aggregated: HashMap<Protocol, HashSet<String>> = HashMap::new();

        // Collect all unique cipher suite names per protocol
        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            for (protocol, summary) in &result.scan_result.ciphers {
                let cipher_set = aggregated.entry(*protocol).or_default();
                for cipher in &summary.supported_ciphers {
                    cipher_set.insert(cipher.openssl_name.clone()); // Necessary: HashSet<String>
                }
            }
        }

        // Convert to ProtocolCipherSummary
        let mut result = HashMap::new();
        for (protocol, _cipher_names) in aggregated {
            // Find any summary from the results to use as template
            let template = self
                .results
                .values()
                .filter(|r| r.error.is_none())
                .find_map(|r| r.scan_result.ciphers.get(&protocol));

            if let Some(template_summary) = template {
                // Collect all CipherSuite objects for this protocol
                // Performance optimization: Use references during iteration, clone only unique ciphers
                let mut unique_ciphers = Vec::new();
                let mut seen = HashSet::new();

                for result in self.results.values() {
                    if result.error.is_some() {
                        continue;
                    }
                    if let Some(summary) = result.scan_result.ciphers.get(&protocol) {
                        for cipher in &summary.supported_ciphers {
                            if seen.insert(&cipher.openssl_name) {
                                unique_ciphers.push(cipher.clone()); // Necessary: building owned Vec
                            }
                        }
                    }
                }

                // Create aggregated summary with recalculated cipher counts
                let mut summary = template_summary.clone(); // Necessary: owned result struct
                summary.supported_ciphers = unique_ciphers;

                // Recalculate ALL cipher counts based on aggregated cipher list
                // This matches the logic in CipherTester::calculate_cipher_counts
                use crate::ciphers::CipherStrength;

                summary.counts.total = summary.supported_ciphers.len();
                summary.counts.null_ciphers = 0;
                summary.counts.export_ciphers = 0;
                summary.counts.low_strength = 0;
                summary.counts.medium_strength = 0;
                summary.counts.high_strength = 0;
                summary.counts.forward_secrecy = 0;
                summary.counts.aead = 0;

                for cipher in &summary.supported_ciphers {
                    match cipher.strength() {
                        CipherStrength::NULL => summary.counts.null_ciphers += 1,
                        CipherStrength::Export => summary.counts.export_ciphers += 1,
                        CipherStrength::Low => summary.counts.low_strength += 1,
                        CipherStrength::Medium => summary.counts.medium_strength += 1,
                        CipherStrength::High => summary.counts.high_strength += 1,
                    }

                    if cipher.has_forward_secrecy() {
                        summary.counts.forward_secrecy += 1;
                    }

                    if cipher.is_aead() {
                        summary.counts.aead += 1;
                    }
                }

                result.insert(protocol, summary);
            }
        }

        result
    }

    /// Aggregate grade conservatively - take the WORST grade
    fn aggregate_grade_conservative(&self) -> (String, u8) {
        let mut worst_grade: Option<(String, u8)> = None;

        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            if let Some(rating) = result.scan_result.ssl_rating() {
                let current_grade = (format!("{}", rating.grade), rating.score);

                match worst_grade {
                    None => worst_grade = Some(current_grade),
                    Some((ref _grade, score)) => {
                        if current_grade.1 < score {
                            worst_grade = Some(current_grade);
                        }
                    }
                }
            }
        }

        worst_grade.unwrap_or_else(|| ("F".to_string(), 0))
    }

    /// Aggregate certificate - return most common certificate
    fn aggregate_certificate(&self) -> Option<CertificateInfo> {
        // Performance optimization: Track counts using references, clone only the winner
        let mut cert_counts: HashMap<&str, (&CertificateInfo, usize)> = HashMap::new();

        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            if let Some(ref cert_chain) = result.scan_result.certificate_chain
                && let Some(cert) = cert_chain.chain.leaf()
                && let Some(ref fingerprint) = cert.fingerprint_sha256
            {
                cert_counts
                    .entry(fingerprint.as_str())
                    .and_modify(|(_, count)| *count += 1)
                    .or_insert((cert, 1));
            }
        }

        // Return the most common certificate (clone only once)
        cert_counts
            .into_iter()
            .max_by_key(|(_, (_, count))| *count)
            .map(|(_, (cert, _))| cert.clone())
    }

    /// Check if all backends serve the same certificate
    fn check_certificate_consistency(&self) -> bool {
        // Performance optimization: Use references instead of cloning fingerprints
        let mut fingerprints = HashSet::new();

        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            if let Some(ref cert_chain) = result.scan_result.certificate_chain
                && let Some(cert) = cert_chain.chain.leaf()
                && let Some(ref fingerprint) = cert.fingerprint_sha256
            {
                fingerprints.insert(fingerprint.as_str());
            }
        }

        fingerprints.len() <= 1
    }

    /// Aggregate ALPN protocols conservatively - intersection of all
    fn aggregate_alpn_conservative(&self) -> Vec<String> {
        let successful_results: Vec<_> = self
            .results
            .values()
            .filter(|r| r.error.is_none())
            .collect();

        if successful_results.is_empty() {
            return Vec::new();
        }

        // Performance optimization: Collect ALPN protocols using references
        let mut protocol_sets: Vec<HashSet<&str>> = Vec::new();

        for result in &successful_results {
            if let Some(alpn_report) = result.scan_result.alpn_result()
                && alpn_report.alpn_enabled
            {
                let protocols: HashSet<&str> = alpn_report
                    .alpn_result
                    .supported_protocols
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                protocol_sets.push(protocols);
            }
        }

        // If no IPs have ALPN enabled, return empty
        if protocol_sets.is_empty() {
            return Vec::new();
        }

        // Find intersection - only protocols supported by ALL IPs
        // Safety: protocol_sets is guaranteed non-empty by check above
        let Some(first_set) = protocol_sets.first() else {
            return Vec::new(); // Unreachable, but explicit for safety
        };
        let intersection: HashSet<&str> = protocol_sets
            .iter()
            .skip(1)
            .fold(first_set.clone(), |acc, set| {
                acc.intersection(set).copied().collect()
            });

        // Convert to sorted vector for consistent output (clone only final strings)
        let mut result: Vec<String> = intersection.into_iter().map(|s| s.to_string()).collect();
        result.sort();
        result
    }

    /// Aggregate session resumption (caching) - only if ALL support it
    fn aggregate_session_resumption_caching(&self) -> bool {
        let successful_results: Vec<_> = self
            .results
            .values()
            .filter(|r| r.error.is_none())
            .collect();

        if successful_results.is_empty() {
            return false;
        }

        successful_results.iter().all(|result| {
            result
                .scan_result
                .protocols
                .iter()
                .any(|p| p.session_resumption_caching == Some(true))
        })
    }

    /// Aggregate session resumption (tickets) - only if ALL support it
    fn aggregate_session_resumption_tickets(&self) -> bool {
        let successful_results: Vec<_> = self
            .results
            .values()
            .filter(|r| r.error.is_none())
            .collect();

        if successful_results.is_empty() {
            return false;
        }

        successful_results.iter().all(|result| {
            result
                .scan_result
                .protocols
                .iter()
                .any(|p| p.session_resumption_tickets == Some(true))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
