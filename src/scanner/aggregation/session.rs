// CipherRun - Conservative Aggregation: Session Resumption Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use std::collections::HashSet;

impl ConservativeAggregator {
    fn aggregate_session_resumption(
        &self,
        selector: impl Fn(&crate::protocols::ProtocolTestResult) -> Option<bool>,
    ) -> Option<bool> {
        let successful_results: Vec<_> = self
            .results
            .values()
            .filter(|r| r.error.is_none())
            .collect();

        if successful_results.is_empty() {
            return None;
        }

        let mut measured_any = false;
        let mut all_support = true;
        let mut had_unknown = false;

        for result in &successful_results {
            let supported_protocols: Vec<_> = result
                .scan_result
                .protocols
                .iter()
                .filter(|protocol| protocol.supported)
                .collect();

            if supported_protocols.is_empty() {
                // Skip IPs with no supported protocols rather than aborting.
                // An IP with no TLS protocols has no session resumption data to contribute.
                continue;
            }

            for protocol in supported_protocols {
                match selector(protocol) {
                    Some(true) => {
                        measured_any = true;
                    }
                    Some(false) => {
                        measured_any = true;
                        all_support = false;
                    }
                    None => {
                        had_unknown = true;
                    }
                }
            }
        }

        if had_unknown && all_support {
            return None;
        }

        measured_any.then_some(all_support)
    }

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

        // Collect ALPN protocol sets for every successful backend.
        // A backend without ALPN enabled (or without an ALPN report) is treated as
        // an empty set to enforce the conservative intersection contract.
        let mut protocol_sets: Vec<HashSet<&str>> = Vec::new();

        for result in &successful_results {
            let protocols = if let Some(alpn_report) = result.scan_result.alpn_result() {
                if alpn_report.alpn_enabled {
                    alpn_report
                        .alpn_result
                        .supported_protocols
                        .iter()
                        .map(|s| s.as_str())
                        .collect()
                } else {
                    HashSet::new()
                }
            } else {
                HashSet::new()
            };

            protocol_sets.push(protocols);
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
        self.aggregate_session_resumption(|protocol| protocol.session_resumption_caching)
    }

    /// Aggregate session resumption (tickets) - only if ALL support it
    pub(super) fn aggregate_session_resumption_tickets(&self) -> Option<bool> {
        self.aggregate_session_resumption(|protocol| protocol.session_resumption_tickets)
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
                        inconclusive: false,
                    },
                    spdy_supported: false,
                    recommendations: Vec::new(),
                    inconclusive: false,
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
    fn test_aggregate_alpn_disabled_across_ips_returns_empty() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let mut results = HashMap::new();

        let mut scan_ip1 = ScanResults {
            advanced: Some(AdvancedResults {
                alpn_result: Some(crate::protocols::alpn::AlpnReport {
                    alpn_enabled: true,
                    alpn_result: crate::protocols::alpn::AlpnResult {
                        supported_protocols: vec!["h2".to_string()],
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
        };
        // Explicitly include a protocol list with protocols to avoid accidental fallback.
        scan_ip1.protocols = vec![ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            inconclusive: false,
            preferred: true,
            ciphers_count: 0,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }];

        let scan_ip2 = ScanResults {
            advanced: Some(AdvancedResults {
                alpn_result: Some(crate::protocols::alpn::AlpnReport {
                    alpn_enabled: false,
                    alpn_result: crate::protocols::alpn::AlpnResult {
                        supported_protocols: vec!["h2".to_string()],
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
        };

        results.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: scan_ip1,
                scan_duration_ms: 1,
                error: None,
            },
        );
        results.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: scan_ip2,
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
            inconclusive: false,
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
            inconclusive: false,
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

    #[test]
    fn test_session_resumption_requires_every_supported_protocol() {
        let ip1: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(127, 0, 0, 2).into();

        let protocols_ip1 = vec![
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 1,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                inconclusive: false,
                preferred: true,
                ciphers_count: 1,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: Some(true),
                session_resumption_tickets: Some(true),
                secure_renegotiation: None,
            },
        ];

        let protocols_ip2 = vec![
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 1,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: Some(true),
                session_resumption_tickets: Some(true),
                secure_renegotiation: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                inconclusive: false,
                preferred: true,
                ciphers_count: 1,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: Some(true),
                session_resumption_tickets: Some(true),
                secure_renegotiation: None,
            },
        ];

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
        assert_eq!(aggregated.session_resumption_tickets, Some(false));
    }
}
