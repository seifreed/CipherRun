use super::{CertificateAnalysisResult, RatingResults, ScanMetadata, ScanResults, Scanner};
use crate::Result;
use crate::rating::RatingCalculator;
use crate::scanner::probe_status::ProbeStatus;
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
        let base_scan = report
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
            target: base_scan.scan_result.target.clone(),
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
        let successful_results: Vec<_> = report
            .per_ip_results
            .values()
            .filter(|result| result.is_successful())
            .collect();

        let attempted_statuses: Vec<_> = successful_results
            .iter()
            .map(|result| &result.scan_result.scan_metadata.probe_status)
            .filter(|status| status.attempts > 0)
            .collect();

        if attempted_statuses.is_empty() {
            return ProbeStatus::default();
        }

        let total_attempts = attempted_statuses
            .iter()
            .map(|status| status.attempts)
            .sum();
        let successful_statuses: Vec<_> = attempted_statuses
            .iter()
            .copied()
            .filter(|status| status.success)
            .collect();

        if let Some(best_success) = successful_statuses
            .iter()
            .copied()
            .min_by_key(|status| status.connection_time_ms.unwrap_or(u64::MAX))
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

        if successful_results
            .iter()
            .any(|result| result.scan_result.has_connection_evidence())
        {
            let best_observed_time_ms = attempted_statuses
                .iter()
                .filter_map(|status| status.connection_time_ms)
                .min()
                .unwrap_or(0);
            let mut aggregated = ProbeStatus::partial_success(
                Duration::from_millis(best_observed_time_ms),
                "Probe/connectivity preflight failed, but later scan phases established a working connection".to_string(),
            );
            aggregated.attempts = total_attempts;
            return aggregated;
        }

        let mut aggregated = (*attempted_statuses[0]).clone();
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

        for result in results.values() {
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

        aggregated
    }

    pub(super) fn select_common_certificate_chain(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
        certificate_info: Option<&crate::certificates::parser::CertificateInfo>,
    ) -> Option<CertificateAnalysisResult> {
        let fingerprint = certificate_info.and_then(|cert| cert.fingerprint_sha256.as_ref());
        let Some(fingerprint) = fingerprint else {
            return results
                .values()
                .filter(|result| result.error.is_none())
                .find_map(|result| result.scan_result.certificate_chain.clone());
        };

        results
            .values()
            .filter(|result| result.error.is_none())
            .find_map(|result| {
                let chain = result.scan_result.certificate_chain.as_ref()?;
                let leaf = chain.chain.leaf()?;
                if leaf.fingerprint_sha256.as_ref()? == fingerprint {
                    Some(chain.clone())
                } else {
                    None
                }
            })
    }
}
