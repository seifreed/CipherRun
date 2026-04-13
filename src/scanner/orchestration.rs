use super::{CertificateAnalysisResult, RatingResults, ScanMetadata, ScanResults, Scanner};
use crate::Result;
use crate::rating::RatingCalculator;
use crate::scanner::probe_status::ProbeStatus;
use crate::utils::network::canonical_target;
use crate::vulnerabilities::{
    VulnerabilityResult, merge_vulnerability_result, merge_vulnerability_result_with_error,
};
use std::time::Duration;

fn collect_scanned_ips(
    report: &crate::scanner::multi_ip::MultiIpScanReport,
) -> Vec<crate::utils::anycast::IpScanResult> {
    let mut per_ip_results: Vec<_> = report
        .per_ip_results
        .values()
        .map(|result| crate::utils::anycast::IpScanResult {
            ip: result.ip,
            results: result.scan_result.clone(),
            error: result.error.clone(),
        })
        .collect();
    per_ip_results.sort_by_key(|result| result.ip);
    per_ip_results
}

impl Scanner {
    /// Run multi-IP scan (scan all IPs in parallel)
    pub(super) async fn run_multi_ip_scan(&self) -> Result<ScanResults> {
        use crate::scanner::multi_ip::MultiIpScanner;

        // Create multi-IP scanner (requires owned values)
        let scanner = MultiIpScanner::new(self.get_target_owned(), self.request.clone());

        // Execute parallel scans
        let report = scanner.scan_all_ips().await?;

        // Use conservative aggregation for multi-IP scans
        let per_ip_results = collect_scanned_ips(&report);

        let mut aggregated = self.build_conservative_multi_ip_result(&report)?;
        aggregated.scan_metadata.scanned_ips = per_ip_results;
        // Store the full report for command layer JSON export
        aggregated.scan_metadata.multi_ip_report = Some(report);
        Ok(aggregated)
    }

    pub(super) fn build_conservative_multi_ip_result(
        &self,
        report: &crate::scanner::multi_ip::MultiIpScanReport,
    ) -> Result<ScanResults> {
        let _base_scan = report
            .per_ip_results
            .values()
            .find(|result| result.is_successful())
            .ok_or_else(|| {
                crate::TlsError::Other(format!("All {} IP address scans failed", report.total_ips))
            })?;

        let certificate_chain = Self::select_common_certificate_chain(
            &report.per_ip_results,
            report.aggregated.certificate_info.as_ref(),
        );

        let mut aggregated = ScanResults {
            target: canonical_target(&report.target.hostname, report.target.port),
            scan_time_ms: report.total_duration_ms,
            protocols: report.aggregated.protocols.clone(),
            ciphers: report.aggregated.ciphers.clone(),
            certificate_chain,
            vulnerabilities: Self::aggregate_vulnerabilities(&report.per_ip_results),
            scan_metadata: ScanMetadata {
                pre_handshake_used: Self::aggregate_pre_handshake_used(&report.per_ip_results),
                probe_status: Self::aggregate_probe_status(report),
                inconsistencies: Some(report.inconsistencies.clone()),
                ..Default::default()
            },
            ..Default::default()
        };

        if self.request.should_calculate_rating() {
            let certificate_validation = aggregated
                .certificate_chain
                .as_ref()
                .map(|cert| &cert.validation);
            aggregated.rating = Some(RatingResults {
                ssl_rating: Some(RatingCalculator::calculate(
                    &aggregated.protocols,
                    &aggregated.ciphers,
                    certificate_validation,
                    &aggregated.vulnerabilities,
                )),
            });
        }

        Ok(aggregated)
    }

    fn aggregate_pre_handshake_used(
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

    fn aggregate_probe_status(report: &crate::scanner::multi_ip::MultiIpScanReport) -> ProbeStatus {
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

    pub(super) fn aggregate_vulnerabilities(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
    ) -> Vec<VulnerabilityResult> {
        let mut aggregated: Vec<VulnerabilityResult> = Vec::new();

        let mut results: Vec<_> = results.iter().collect();
        results.sort_by_key(|(ip, _)| **ip);

        for (_, result) in results {
            let has_error = result.error.is_some();
            if has_error && result.scan_result.vulnerabilities.is_empty() {
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
                            merge_vulnerability_result_with_error(item, vuln, "partial scan");
                        } else {
                            merge_vulnerability_result(item, vuln);
                        }
                    }
                }
            }
        }

        // Sort by vulnerability type for deterministic output
        aggregated.sort_by_key(|v| v.vuln_type.sort_key());

        aggregated
    }

    pub(super) fn select_common_certificate_chain(
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
                    let signature = super::aggregation::certificate_chain_signature(&chain.chain);
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

        Self::select_most_common_certificate_chain(&candidate_chains)
            .or_else(|| successful_chains.first().map(|(_, chain, _)| chain.clone()))
    }

    fn select_most_common_certificate_chain(
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

#[cfg(test)]
mod tests {
    use super::collect_scanned_ips;
    use crate::scanner::ScanResults;
    use crate::scanner::aggregation::AggregatedScanResult;
    use crate::scanner::inconsistency::SingleIpScanResult;
    use crate::scanner::multi_ip::MultiIpScanReport;
    use crate::utils::network::Target;
    use std::collections::HashMap;
    use std::net::IpAddr;

    #[test]
    fn test_collect_scanned_ips_sorts_by_ip() {
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();

        let target = Target::with_ips("example.com".to_string(), 443, vec![ip1, ip2]).unwrap();

        let mut per_ip_results = HashMap::new();
        per_ip_results.insert(
            ip2,
            SingleIpScanResult {
                ip: ip2,
                scan_result: ScanResults::default(),
                scan_duration_ms: 20,
                error: None,
            },
        );
        per_ip_results.insert(
            ip1,
            SingleIpScanResult {
                ip: ip1,
                scan_result: ScanResults::default(),
                scan_duration_ms: 10,
                error: None,
            },
        );

        let report = MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 2,
            successful_scans: 2,
            failed_scans: 0,
            total_duration_ms: 30,
            inconsistencies: Vec::new(),
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("F".to_string(), 0),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
        };

        let scanned_ips = collect_scanned_ips(&report);
        assert_eq!(scanned_ips[0].ip, ip1);
        assert_eq!(scanned_ips[1].ip, ip2);
    }
}
