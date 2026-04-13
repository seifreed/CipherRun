// CipherRun - Conservative Aggregation: Certificate Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use crate::certificates::parser::CertificateInfo;
use std::collections::{BTreeSet, HashMap};

impl ConservativeAggregator {
    /// Aggregate certificate - return the leaf from the most common full chain
    pub(super) fn aggregate_certificate(&self) -> Option<CertificateInfo> {
        // Performance optimization: Track counts using references, clone only the winner.
        // Full-chain signatures are used so that chain differences are not collapsed
        // when the leaf certificate is the same.
        let mut cert_counts: HashMap<String, (&CertificateInfo, usize)> = HashMap::new();

        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            if let Some(ref cert_chain) = result.scan_result.certificate_chain
                && let Some(cert) = cert_chain.chain.leaf()
            {
                let signature = super::certificate_chain_signature(&cert_chain.chain);
                cert_counts
                    .entry(signature)
                    .and_modify(|(_, count)| *count += 1)
                    .or_insert((cert, 1));
            }
        }

        // Return the most common certificate (clone only once).
        // Ties are resolved deterministically by lexicographic chain-signature order.
        cert_counts
            .into_iter()
            .max_by(|(signature_a, (_, count_a)), (signature_b, (_, count_b))| {
                count_a
                    .cmp(count_b)
                    .then_with(|| signature_b.cmp(signature_a))
            })
            .map(|(_, (cert, _))| cert.clone())
    }

    /// Check if all backends serve the same certificate chain
    pub(super) fn check_certificate_consistency(&self) -> bool {
        let mut signatures = BTreeSet::new();
        let mut saw_certificate = false;
        let mut saw_missing_certificate = false;

        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            if let Some(ref cert_chain) = result.scan_result.certificate_chain {
                saw_certificate = true;
                signatures.insert(super::certificate_chain_signature(&cert_chain.chain));
            } else {
                saw_missing_certificate = true;
            }
        }

        if saw_certificate && saw_missing_certificate {
            return false;
        }

        signatures.len() <= 1
    }
}
