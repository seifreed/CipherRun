use super::{CertificateAnalysisResult, RatingResults, ScanMetadata, ScanResults, Scanner};
use crate::Result;
use crate::rating::RatingCalculator;
use crate::scanner::probe_status::ProbeStatus;
use crate::utils::network::canonical_target;
use crate::vulnerabilities::{VulnerabilityResult, merge_vulnerability_result};
use std::time::Duration;

impl Scanner {
    /// Run multi-IP scan (scan all IPs in parallel)
    pub(super) async fn run_multi_ip_scan(&self) -> Result<ScanResults> {
        use crate::scanner::multi_ip::MultiIpScanner;

        // Create multi-IP scanner (requires owned values)
        let scanner = MultiIpScanner::new(self.get_target_owned(), self.request.clone());

        // Execute parallel scans
        let report = scanner.scan_all_ips().await?;

        // Use conservative aggregation for multi-IP scans
        let per_ip_results: Vec<_> = report
            .per_ip_results
            .values()
            .map(|result| crate::utils::anycast::IpScanResult {
                ip: result.ip,
                results: result.scan_result.clone(),
                error: result.error.clone(),
            })
            .collect();

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
            if result.error.is_some() && result.scan_result.vulnerabilities.is_empty() {
                continue;
            }

            for vuln in &result.scan_result.vulnerabilities {
                let existing = aggregated
                    .iter_mut()
                    .find(|item| item.vuln_type == vuln.vuln_type);

                match existing {
                    None => aggregated.push(vuln.clone()),
                    Some(item) => merge_vulnerability_result(item, vuln),
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
                result
                    .scan_result
                    .certificate_chain
                    .clone()
                    .map(|chain| (*ip, chain))
            })
            .collect();

        successful_chains.sort_by_key(|(ip, _)| *ip);

        let successful_chains: Vec<_> = successful_chains
            .into_iter()
            .map(|(_, chain)| chain)
            .collect();

        if successful_chains.is_empty() {
            return None;
        }

        // Detect certificate inconsistencies across IPs
        let first_fingerprint = successful_chains
            .first()
            .and_then(|chain| chain.chain.leaf())
            .and_then(|cert| cert.fingerprint_sha256.as_ref());

        let has_inconsistencies = successful_chains.iter().skip(1).any(|chain| {
            let current_fingerprint = chain
                .chain
                .leaf()
                .and_then(|cert| cert.fingerprint_sha256.as_ref());
            current_fingerprint != first_fingerprint
        });

        if has_inconsistencies {
            tracing::warn!(
                "Certificate inconsistency detected across IPs - different certificates served. \
                 Using first available certificate for reporting. \
                 This may indicate load balancing or SNI-based certificate selection."
            );
        }

        // Use the provided fingerprint if available, otherwise use first chain's fingerprint
        let fingerprint = certificate_info.and_then(|cert| cert.fingerprint_sha256.as_ref());
        let target_fingerprint = fingerprint.or(first_fingerprint);

        let Some(target_fingerprint) = target_fingerprint else {
            // No fingerprint available, return first successful chain
            return successful_chains.first().cloned();
        };

        Self::select_chain_by_fingerprint(&successful_chains, target_fingerprint.as_str())
            .or_else(|| successful_chains.first().cloned())
    }

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
