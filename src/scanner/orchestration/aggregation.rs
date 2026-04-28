use super::super::{CertificateAnalysisResult, Scanner};
use crate::scanner::probe_status::ProbeStatus;
use crate::vulnerabilities::{
    VulnerabilityResult, merge_vulnerability_result, merge_vulnerability_result_with_error,
};
use std::time::Duration;

impl Scanner {
    pub(super) fn aggregate_pre_handshake_used(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
    ) -> bool {
        results
            .values()
            .filter(|result| result.is_successful())
            .any(|result| result.scan_result.scan_metadata.pre_handshake_used)
    }

    pub(super) fn aggregate_probe_status(
        report: &crate::scanner::multi_ip::MultiIpScanReport,
    ) -> ProbeStatus {
        let mut successful_results: Vec<_> = report
            .per_ip_results
            .iter()
            .filter(|(_, result)| result.is_successful())
            .collect();

        successful_results.sort_by_key(|(ip, _)| **ip);

        let has_connection_evidence = successful_results
            .iter()
            .any(|(_, result)| result.scan_result.has_connection_evidence());

        let attempted_statuses: Vec<_> = successful_results
            .iter()
            .map(|(ip, result)| (*ip, &result.scan_result.scan_metadata.probe_status))
            .filter(|(_, status)| status.attempts > 0)
            .collect();

        if attempted_statuses.is_empty() {
            if has_connection_evidence {
                let mut aggregated = ProbeStatus::partial_success(
                    Duration::from_millis(0),
                    "Probe/connectivity preflight failed, but later scan phases established a working connection".to_string(),
                );
                aggregated.attempts = 0;
                return aggregated;
            }
            return ProbeStatus::default();
        }

        let total_attempts: u32 = attempted_statuses
            .iter()
            .map(|(_, status)| status.attempts)
            .sum();
        let successful_statuses: Vec<_> = attempted_statuses
            .iter()
            .copied()
            .filter(|(_, status)| status.success)
            .collect();

        if let Some((_, best_success)) = successful_statuses
            .iter()
            .copied()
            .min_by_key(|(ip, status)| (status.connection_time_ms.unwrap_or(u64::MAX), *ip))
        {
            let had_partial_failures = successful_statuses.len() < attempted_statuses.len();
            let had_failed_ip_scans = report.failed_scans > 0;
            let probe_error_count = attempted_statuses.len() - successful_statuses.len();
            let degraded_count = report.failed_scans + probe_error_count;
            let mut aggregated = if had_partial_failures || had_failed_ip_scans {
                ProbeStatus::partial_success(
                    Duration::from_millis(best_success.connection_time_ms.unwrap_or(0)),
                    format!(
                        "Connectivity succeeded for {} successful IP scans; {} IP scans failed or had probe errors",
                        report.successful_scans, degraded_count
                    ),
                )
            } else {
                (*best_success).clone()
            };
            aggregated.attempts = total_attempts;
            return aggregated;
        }

        if has_connection_evidence {
            let best_observed_time_ms = attempted_statuses
                .iter()
                .filter_map(|(_, status)| status.connection_time_ms)
                .min()
                .unwrap_or(0);
            let mut aggregated = ProbeStatus::partial_success(
                Duration::from_millis(best_observed_time_ms),
                "Probe/connectivity preflight failed, but later scan phases established a working connection".to_string(),
            );
            aggregated.attempts = total_attempts;
            return aggregated;
        }

        let mut aggregated = attempted_statuses[0].1.clone();
        aggregated.attempts = total_attempts;
        aggregated
    }

    pub(in super::super) fn aggregate_vulnerabilities(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
    ) -> Vec<VulnerabilityResult> {
        let mut aggregated: Vec<VulnerabilityResult> = Vec::new();
        let mut incomplete_backend_coverage = false;

        let mut results: Vec<_> = results.iter().collect();
        results.sort_by_key(|(ip, _)| **ip);

        for (_, result) in results {
            let has_error = result.error.is_some();
            if has_error && result.scan_result.vulnerabilities.is_empty() {
                incomplete_backend_coverage = true;
                continue;
            }

            for vuln in &result.scan_result.vulnerabilities {
                let existing = aggregated
                    .iter_mut()
                    .find(|item| item.vuln_type == vuln.vuln_type);

                match existing {
                    None => {
                        let mut vuln = vuln.clone();
                        if has_error {
                            vuln.inconclusive = true;
                            if !vuln.details.contains("partial scan") {
                                vuln.details = format!(
                                    "{} (from partial scan - some checks may be incomplete)",
                                    vuln.details
                                );
                            }
                        }
                        aggregated.push(vuln);
                    }
                    Some(item) => {
                        if has_error {
                            incomplete_backend_coverage = true;
                            merge_vulnerability_result_with_error(item, vuln, "partial scan");
                        } else {
                            merge_vulnerability_result(item, vuln);
                        }
                    }
                }
            }
        }

        if incomplete_backend_coverage {
            for vulnerability in &mut aggregated {
                // Only append the coverage warning; vulnerabilities confirmed
                // on successful backends remain conclusive.
                if !vulnerability
                    .details
                    .contains("incomplete backend coverage")
                {
                    vulnerability.details = format!(
                        "{}; incomplete backend coverage - at least one IP backend failed during scanning",
                        vulnerability.details
                    );
                }
            }
        }

        // Sort by vulnerability type for deterministic output
        aggregated.sort_by_key(|v| v.vuln_type.sort_key());

        aggregated
    }

    pub(in super::super) fn select_common_certificate_chain(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
        certificate_info: Option<&crate::certificates::parser::CertificateInfo>,
    ) -> Option<CertificateAnalysisResult> {
        // Collect all successful certificate chains for analysis
        let mut successful_chains: Vec<_> = results
            .iter()
            .filter(|(_, result)| result.error.is_none())
            .filter_map(|(ip, result)| {
                result.scan_result.certificate_chain.clone().map(|chain| {
                    let signature =
                        crate::scanner::aggregation::certificate_chain_signature(&chain.chain);
                    (*ip, chain, signature)
                })
            })
            .collect();

        successful_chains.sort_by_key(|(ip, _, _)| *ip);

        if successful_chains.is_empty() {
            return None;
        }

        let has_inconsistencies = successful_chains
            .iter()
            .map(|(_, _, signature)| signature.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1;

        if has_inconsistencies {
            tracing::warn!(
                "Certificate inconsistency detected across IPs - different certificate chains served. \
                 Using a representative certificate chain for reporting. \
                 This may indicate load balancing or SNI-based certificate selection."
            );
        }

        let target_leaf_fingerprint =
            certificate_info.and_then(|cert| cert.fingerprint_sha256.as_deref());

        let candidate_chains: Vec<_> =
            if let Some(target_leaf_fingerprint) = target_leaf_fingerprint {
                let matching: Vec<_> = successful_chains
                    .iter()
                    .filter(|(_, chain, _)| {
                        chain
                            .chain
                            .leaf()
                            .and_then(|cert| cert.fingerprint_sha256.as_deref())
                            == Some(target_leaf_fingerprint)
                    })
                    .cloned()
                    .collect();

                if matching.is_empty() {
                    successful_chains.clone()
                } else {
                    matching
                }
            } else {
                successful_chains.clone()
            };

        Scanner::select_most_common_certificate_chain(&candidate_chains)
            .or_else(|| successful_chains.first().map(|(_, chain, _)| chain.clone()))
    }
}
