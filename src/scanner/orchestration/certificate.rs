use super::super::{CertificateAnalysisResult, Scanner};

impl Scanner {
    pub(super) fn select_most_common_certificate_chain(
        successful_chains: &[(std::net::IpAddr, CertificateAnalysisResult, String)],
    ) -> Option<CertificateAnalysisResult> {
        use std::collections::BTreeMap;

        let mut chain_counts: BTreeMap<String, (usize, CertificateAnalysisResult)> =
            BTreeMap::new();

        for (_, chain, signature) in successful_chains {
            chain_counts
                .entry(signature.clone())
                .and_modify(|(count, _)| *count += 1)
                .or_insert((1, chain.clone()));
        }

        chain_counts
            .into_iter()
            .max_by(|(signature_a, (count_a, _)), (signature_b, (count_b, _))| {
                count_a
                    .cmp(count_b)
                    .then_with(|| signature_b.cmp(signature_a))
            })
            .map(|(_, (_, chain))| chain)
    }

    #[cfg(test)]
    pub(crate) fn select_chain_by_fingerprint(
        successful_chains: &[CertificateAnalysisResult],
        target_fingerprint: &str,
    ) -> Option<CertificateAnalysisResult> {
        successful_chains.iter().find_map(|chain| {
            let leaf = chain.chain.leaf()?;
            (leaf.fingerprint_sha256.as_deref() == Some(target_fingerprint)).then(|| chain.clone())
        })
    }
}
