// CipherRun - Conservative Aggregation: Cipher Suite Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::ciphers::{CipherStrength, CipherSuite};
use crate::protocols::Protocol;
use std::collections::{HashMap, HashSet};

impl ConservativeAggregator {
    /// Aggregate cipher suites conservatively - union of all ciphers
    pub(super) fn aggregate_ciphers_conservative(
        &self,
    ) -> HashMap<Protocol, ProtocolCipherSummary> {
        let mut result = HashMap::new();
        let mut successful_results: Vec<_> = self
            .results
            .iter()
            .filter(|(_, r)| r.error.is_none())
            .collect();
        successful_results.sort_by_key(|(ip, _)| **ip);

        for protocol in Protocol::all() {
            let protocol_summaries: Vec<_> = successful_results
                .iter()
                .filter_map(|(_, result)| result.scan_result.ciphers.get(&protocol))
                .collect();

            if protocol_summaries.is_empty() {
                continue;
            }

            let mut unique_ciphers = Vec::new();
            let mut seen = HashSet::new();

            for summary in &protocol_summaries {
                for cipher in &summary.supported_ciphers {
                    if seen.insert(cipher.openssl_name.clone()) {
                        unique_ciphers.push(cipher.clone());
                    }
                }
            }

            let all_server_ordered = protocol_summaries
                .iter()
                .all(|summary| summary.server_ordered);
            let server_preference = consensus_server_preference(&protocol_summaries);
            let preferred_cipher = if all_server_ordered {
                consensus_preferred_cipher(&protocol_summaries)
            } else {
                None
            };
            let avg_handshake_time_ms = protocol_summaries
                .iter()
                .filter_map(|summary| summary.avg_handshake_time_ms)
                .max();

            let mut summary = ProtocolCipherSummary {
                protocol,
                supported_ciphers: unique_ciphers,
                server_ordered: all_server_ordered,
                server_preference,
                preferred_cipher,
                counts: Default::default(),
                avg_handshake_time_ms,
            };

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

        result
    }
}

fn consensus_server_preference(summaries: &[&ProtocolCipherSummary]) -> Vec<String> {
    let Some(first) = summaries.first() else {
        return Vec::new();
    };

    if summaries
        .iter()
        .all(|summary| summary.server_preference == first.server_preference)
    {
        first.server_preference.clone()
    } else {
        Vec::new()
    }
}

fn consensus_preferred_cipher(summaries: &[&ProtocolCipherSummary]) -> Option<CipherSuite> {
    let first = summaries.first()?.preferred_cipher.as_ref()?;
    let signature = cipher_signature(first);

    if summaries
        .iter()
        .all(|summary| summary.preferred_cipher.as_ref().map(cipher_signature) == Some(signature))
    {
        Some(first.clone())
    } else {
        None
    }
}

fn cipher_signature(
    cipher: &CipherSuite,
) -> (&str, &str, &str, &str, &str, &str, &str, &str, u16, bool) {
    (
        cipher.hexcode.as_str(),
        cipher.openssl_name.as_str(),
        cipher.iana_name.as_str(),
        cipher.protocol.as_str(),
        cipher.key_exchange.as_str(),
        cipher.authentication.as_str(),
        cipher.encryption.as_str(),
        cipher.mac.as_str(),
        cipher.bits,
        cipher.export,
    )
}
