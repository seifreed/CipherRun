// CipherRun - Conservative Aggregation: Protocol Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use crate::protocols::{Protocol, ProtocolTestResult};

impl ConservativeAggregator {
    /// Aggregate protocols conservatively - only protocols supported by ALL IPs
    pub(super) fn aggregate_protocols_conservative(&self) -> Vec<ProtocolTestResult> {
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
}
