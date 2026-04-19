// CipherRun - Conservative Aggregation: Protocol Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use crate::protocols::{Protocol, ProtocolTestResult};
use std::collections::HashSet;

impl ConservativeAggregator {
    /// Aggregate protocols conservatively - only protocols supported by ALL IPs
    pub(super) fn aggregate_protocols_conservative(&self) -> Vec<ProtocolTestResult> {
        let mut aggregated = Vec::new();

        // Get all successful results
        let mut successful_results: Vec<_> = self
            .results
            .iter()
            .filter(|(_, r)| r.error.is_none())
            .collect();
        successful_results.sort_by_key(|(ip, _)| **ip);

        if successful_results.is_empty() {
            return aggregated;
        }

        // For each protocol, check if ALL IPs support it
        for protocol in Protocol::all() {
            let protocol_results: Vec<_> = successful_results
                .iter()
                .filter_map(|(_, result)| {
                    result
                        .scan_result
                        .protocols
                        .iter()
                        .find(|p| p.protocol == protocol)
                })
                .collect();

            let all_support = protocol_results.len() == successful_results.len()
                && protocol_results.iter().all(|result| result.supported);

            // Take the best protocol test result details if supported by all
            if all_support {
                let ciphers_count = successful_results
                    .iter()
                    .filter_map(|(_, result)| result.scan_result.ciphers.get(&protocol))
                    .flat_map(|summary| {
                        summary
                            .supported_ciphers
                            .iter()
                            .map(|cipher| cipher.openssl_name.as_str())
                    })
                    .collect::<HashSet<_>>()
                    .len();

                let preferred_count = protocol_results.iter().filter(|r| r.preferred).count();
                let preferred =
                    !protocol_results.is_empty() && preferred_count * 2 > protocol_results.len();
                let handshake_time_ms = protocol_results
                    .iter()
                    .filter_map(|result| result.handshake_time_ms)
                    .max();
                let heartbeat_enabled = consensus_optional_bool(
                    protocol_results
                        .iter()
                        .copied()
                        .map(|result| result.heartbeat_enabled),
                );
                let session_resumption_caching = consensus_optional_bool(
                    protocol_results
                        .iter()
                        .copied()
                        .map(|result| result.session_resumption_caching),
                );
                let session_resumption_tickets = consensus_optional_bool(
                    protocol_results
                        .iter()
                        .copied()
                        .map(|result| result.session_resumption_tickets),
                );
                let secure_renegotiation = consensus_optional_bool(
                    protocol_results
                        .iter()
                        .copied()
                        .map(|result| result.secure_renegotiation),
                );

                aggregated.push(ProtocolTestResult {
                    protocol,
                    supported: true,
                    preferred,
                    ciphers_count,
                    handshake_time_ms,
                    heartbeat_enabled,
                    session_resumption_caching,
                    session_resumption_tickets,
                    secure_renegotiation,
                });
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
}

fn consensus_optional_bool(values: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
    let mut seen: Option<bool> = None;

    for value in values {
        let value = value?;

        match seen {
            None => seen = Some(value),
            Some(existing) if existing == value => {}
            Some(_) => return None,
        }
    }

    seen
}
