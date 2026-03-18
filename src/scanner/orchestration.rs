use super::{CertificateAnalysisResult, RatingResults, ScanResults, Scanner};
use crate::Result;
use crate::rating::RatingCalculator;
use crate::vulnerabilities::{VulnerabilityResult, merge_vulnerability_result};

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
        aggregated.scanned_ips = per_ip_results;
        // Store the full report for command layer JSON export
        aggregated.multi_ip_report = Some(report);
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

        let mut aggregated = base_scan.scan_result.clone();

        aggregated.protocols = report.aggregated.protocols.clone();
        aggregated.ciphers = report.aggregated.ciphers.clone();
        aggregated.vulnerabilities = Self::aggregate_vulnerabilities(&report.per_ip_results);
        aggregated.certificate_chain = Self::select_common_certificate_chain(
            &report.per_ip_results,
            report.aggregated.certificate_info.as_ref(),
        );
        aggregated.inconsistencies = Some(report.inconsistencies.clone());

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

        Ok(aggregated)
    }

    pub(super) fn aggregate_vulnerabilities(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
    ) -> Vec<VulnerabilityResult> {
        let mut aggregated: Vec<VulnerabilityResult> = Vec::new();

        for result in results.values() {
            if result.error.is_some() {
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
