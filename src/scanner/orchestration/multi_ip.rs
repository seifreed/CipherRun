use super::super::{RatingResults, ScanMetadata, ScanResults, Scanner};
use super::collect_scanned_ips;
use crate::Result;
use crate::rating::RatingCalculator;
use crate::utils::network::canonical_target;

impl Scanner {
    /// Run multi-IP scan (scan all IPs in parallel)
    pub(in super::super) async fn run_multi_ip_scan(&self) -> Result<ScanResults> {
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

    pub(in super::super) fn build_conservative_multi_ip_result(
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

        let certificate_chain = Scanner::select_common_certificate_chain(
            &report.per_ip_results,
            report.aggregated.certificate_info.as_ref(),
        );

        let mut aggregated = ScanResults {
            target: canonical_target(&report.target.hostname, report.target.port),
            scan_time_ms: report.total_duration_ms,
            protocols: report.aggregated.protocols.clone(),
            ciphers: report.aggregated.ciphers.clone(),
            certificate_chain,
            vulnerabilities: Scanner::aggregate_vulnerabilities(&report.per_ip_results),
            scan_metadata: ScanMetadata {
                pre_handshake_used: Scanner::aggregate_pre_handshake_used(&report.per_ip_results),
                probe_status: Scanner::aggregate_probe_status(report),
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
}
