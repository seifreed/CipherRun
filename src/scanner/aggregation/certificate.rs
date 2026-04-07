// CipherRun - Conservative Aggregation: Certificate Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use crate::certificates::parser::CertificateInfo;
use std::collections::HashMap;
use std::collections::HashSet;

impl ConservativeAggregator {
    /// Aggregate certificate - return most common certificate
    pub(super) fn aggregate_certificate(&self) -> Option<CertificateInfo> {
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
    pub(super) fn check_certificate_consistency(&self) -> bool {
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
}
