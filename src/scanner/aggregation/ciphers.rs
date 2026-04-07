// CipherRun - Conservative Aggregation: Cipher Suite Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::Protocol;
use std::collections::{HashMap, HashSet};

impl ConservativeAggregator {
    /// Aggregate cipher suites conservatively - union of all ciphers
    pub(super) fn aggregate_ciphers_conservative(&self) -> HashMap<Protocol, ProtocolCipherSummary> {
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
}
