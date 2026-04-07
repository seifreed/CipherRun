// CipherRun - Conservative Aggregation: Session Resumption Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use std::collections::HashSet;

impl ConservativeAggregator {
    /// Aggregate ALPN protocols conservatively - intersection of all
    pub(super) fn aggregate_alpn_conservative(&self) -> Vec<String> {
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
    pub(super) fn aggregate_session_resumption_caching(&self) -> Option<bool> {
        let successful_results: Vec<_> = self
            .results
            .values()
            .filter(|r| r.error.is_none())
            .collect();

        if successful_results.is_empty() {
            return None;
        }

        let mut measured_protocols = 0usize;
        let mut all_support = true;

        for result in &successful_results {
            let mut backend_measured = false;

            for protocol in result.scan_result.protocols.iter().filter(|p| p.supported) {
                if let Some(supported) = protocol.session_resumption_caching {
                    backend_measured = true;
                    measured_protocols += 1;
                    all_support &= supported;
                }
            }

            if !backend_measured {
                return None;
            }
        }

        if measured_protocols == 0 {
            None
        } else {
            Some(all_support)
        }
    }

    /// Aggregate session resumption (tickets) - only if ALL support it
    pub(super) fn aggregate_session_resumption_tickets(&self) -> Option<bool> {
        let successful_results: Vec<_> = self
            .results
            .values()
            .filter(|r| r.error.is_none())
            .collect();

        if successful_results.is_empty() {
            return None;
        }

        let mut measured_protocols = 0usize;
        let mut all_support = true;

        for result in &successful_results {
            let mut backend_measured = false;

            for protocol in result.scan_result.protocols.iter().filter(|p| p.supported) {
                if let Some(supported) = protocol.session_resumption_tickets {
                    backend_measured = true;
                    measured_protocols += 1;
                    all_support &= supported;
                }
            }
            if !backend_measured {
                return None;
            }
        }

        if measured_protocols == 0 {
            None
        } else {
            Some(all_support)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::super::*;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::rating::grader::Grade;
    use crate::scanner::inconsistency::SingleIpScanResult;
    use crate::scanner::{AdvancedResults, ScanResults};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_aggregate_alpn_disabled_returns_empty() {
        let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let scan = ScanResults {
            advanced: Some(AdvancedResults {
                alpn_result: Some(crate::protocols::alpn::AlpnReport {
                    alpn_enabled: false,
                    alpn_result: crate::protocols::alpn::AlpnResult {
                        supported_protocols: vec!["h2".to_string()],
                        http2_supported: true,
                        http3_supported: false,
                        negotiated_protocol: None,
                        details: Vec::new(),
                    },
                    spdy_supported: false,
                    recommendations: Vec::new(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut results = HashMap::new();
        results.insert(
            ip,
            SingleIpScanResult {
                ip,
                scan_result: scan,
                scan_duration_ms: 1,
                error: None,
            },
        );

        let aggregator = ConservativeAggregator::new(results, Vec::new());
        let aggregated = aggregator.aggregate();
        assert!(aggregated.alpn_protocols.is_empty());
    }

    #[test]
    fn test_session_resumption_requires_all_support() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let protocols_ip1 = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: Some(true),
            session_resumption_tickets: Some(true),
            secure_renegotiation: None,
        }];

        let protocols_ip2 = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: Some(false),
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
        assert_eq!(aggregated.session_resumption_caching, Some(false));
        assert_eq!(aggregated.session_resumption_tickets, None);
    }
}
