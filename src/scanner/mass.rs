// Mass Scanner - Parallel and serial scanning of multiple targets

#[path = "mass/progress.rs"]
mod progress;

pub use progress::{
    MassScanProgressCallback, SilentMassProgress, TargetScanProgress, TerminalMassProgress,
};

use crate::Result;
use crate::application::{CertificateFilters, ScanRequest};
use crate::certificates::status::CertificateStatus;
use crate::scanner::{ScanResults, Scanner};
use crate::utils::network::split_target_host_port;
use crate::utils::network_runtime;
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::Semaphore;

type ScanTask = (
    String,
    tokio::task::JoinHandle<(String, Result<ScanResults>)>,
);

/// Mass scanner for scanning multiple targets
///
/// Performance optimization: Uses Arc<ScanRequest> to avoid expensive cloning
/// in parallel scanning operations.
#[derive(Debug, Clone)]
pub struct MassScanConfig {
    pub max_parallel: usize,
    pub certificate_filters: CertificateFilters,
}

impl Default for MassScanConfig {
    fn default() -> Self {
        Self {
            max_parallel: 20,
            certificate_filters: CertificateFilters::default(),
        }
    }
}

pub struct MassScanner {
    request: Arc<ScanRequest>,
    config: MassScanConfig,
    pub targets: Vec<String>,
    callback: Option<Arc<dyn MassScanProgressCallback>>,
}

impl MassScanner {
    /// Create a new mass scanner
    pub fn new(request: ScanRequest, config: MassScanConfig, targets: Vec<String>) -> Self {
        Self {
            request: Arc::new(request),
            config,
            targets,
            callback: None,
        }
    }

    /// Load targets from file
    pub fn from_file(
        request: ScanRequest,
        config: MassScanConfig,
        file_path: &str,
    ) -> Result<Self> {
        let content = std::fs::read_to_string(file_path)?;
        let targets: Vec<String> = content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect();

        if targets.is_empty() {
            return Err(crate::error::TlsError::Other(format!(
                "No targets found in file: {}",
                file_path
            )));
        }

        Ok(Self {
            request: Arc::new(request),
            config,
            targets,
            callback: None,
        })
    }

    /// Set progress callback for receiving scan updates
    pub fn with_callback(mut self, callback: Arc<dyn MassScanProgressCallback>) -> Self {
        self.callback = Some(callback);
        self
    }

    /// Set terminal progress callback (convenience method)
    pub fn with_terminal_progress(self) -> Self {
        self.with_callback(Arc::new(TerminalMassProgress::new()))
    }

    /// Scan all targets serially
    pub async fn scan_serial(&self) -> Result<Vec<(String, Result<ScanResults>)>> {
        let total = self.targets.len();

        // Notify callback of scan start
        if let Some(ref callback) = self.callback {
            callback.on_serial_scan_start(total);
        }

        let mut results = Vec::new();

        for (idx, target) in self.targets.iter().enumerate() {
            let index = idx + 1;

            // Notify callback of target start
            if let Some(ref callback) = self.callback {
                callback.on_target_start(target, index, total);
            }

            let start = std::time::Instant::now();
            let result = self.scan_single_target(target).await;
            let duration = start.elapsed();

            // Notify callback of target completion
            if let Some(ref callback) = self.callback {
                let progress = TargetScanProgress {
                    target,
                    index,
                    total,
                    result: &result,
                    duration,
                };
                callback.on_target_complete(&progress);
            }

            results.push((target.clone(), result));
        }

        Ok(results)
    }

    /// Scan all targets in parallel
    pub async fn scan_parallel(&self) -> Result<Vec<(String, Result<ScanResults>)>> {
        let max_parallel = self.config.max_parallel;
        let total = self.targets.len();

        if let Some(ref callback) = self.callback {
            callback.on_parallel_scan_start(total, max_parallel);
        }

        let (multi_progress, main_pb) = Self::create_scan_progress_bars(total);
        let semaphore = Arc::new(Semaphore::new(max_parallel.max(1)));
        let tasks = self.spawn_scan_tasks(&semaphore, &multi_progress);
        let results = self.collect_scan_results(tasks, &main_pb, total).await;

        main_pb.finish_with_message("All scans completed");
        if let Some(ref callback) = self.callback {
            callback.on_all_scans_complete();
        }

        Ok(results)
    }

    fn create_scan_progress_bars(total: usize) -> (Arc<MultiProgress>, ProgressBar) {
        let multi_progress = Arc::new(MultiProgress::new());
        let main_pb = multi_progress.add(ProgressBar::new(total as u64));
        main_pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                .expect("hardcoded progress bar template is valid")
                .progress_chars("=>-"),
        );
        (multi_progress, main_pb)
    }

    fn spawn_scan_tasks(
        &self,
        semaphore: &Arc<Semaphore>,
        multi_progress: &Arc<MultiProgress>,
    ) -> Vec<ScanTask> {
        let mut tasks = Vec::new();

        for target in &self.targets {
            let target_for_task = target.clone();
            let target_for_tracking = target.clone();
            let semaphore = Arc::clone(semaphore);
            let request = Arc::clone(&self.request);
            let multi_progress = Arc::clone(multi_progress);

            let task = tokio::spawn(async move {
                let _permit = match semaphore.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        return (
                            target_for_task,
                            Err(crate::error::TlsError::ParseError {
                                message: "Scanner shutdown - semaphore closed".to_string(),
                            }),
                        );
                    }
                };

                let pb = multi_progress.add(ProgressBar::new_spinner());
                pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .expect("hardcoded spinner template is valid"),
                );
                pb.set_message(format!("Scanning {}", target_for_task));

                let result: Result<_> =
                    network_runtime::scope_proxy(request.network.proxy.clone(), async {
                        match MassScanner::create_scanner(&request, &target_for_task) {
                            Ok(s) => s.run().await,
                            Err(e) => Err(e),
                        }
                    })
                    .await;

                pb.finish_and_clear();
                (target_for_task, result)
            });

            tasks.push((target_for_tracking, task));
        }

        tasks
    }

    async fn collect_scan_results(
        &self,
        tasks: Vec<ScanTask>,
        main_pb: &ProgressBar,
        total: usize,
    ) -> Vec<(String, Result<ScanResults>)> {
        let mut results = Vec::new();

        for (target_name, task) in tasks {
            let (target, result) = match task.await {
                Ok(r) => r,
                Err(join_err) => {
                    tracing::error!(
                        "Scan task panicked for target {}: {}",
                        target_name,
                        join_err
                    );
                    main_pb.inc(1);
                    if let Some(ref callback) = self.callback {
                        callback.on_parallel_progress(results.len() + 1, total, &target_name);
                    }
                    results.push((
                        target_name.clone(),
                        Err(crate::error::TlsError::ParseError {
                            message: format!("Scan task panicked: {}", join_err),
                        }),
                    ));
                    main_pb.set_message(format!("Failed: {}", target_name));
                    continue;
                }
            };

            main_pb.inc(1);
            if let Some(ref callback) = self.callback {
                callback.on_parallel_progress(results.len() + 1, total, &target);
            }
            main_pb.set_message(format!("Completed: {}", target));
            results.push((target, result));
        }

        results
    }

    /// Scan a single target
    async fn scan_single_target(&self, target: &str) -> Result<ScanResults> {
        let scanner = Self::create_scanner(&self.request, target)?;
        scanner.run().await
    }

    /// Create a scanner for a specific target
    fn create_scanner(request: &Arc<ScanRequest>, target: &str) -> Result<Scanner> {
        let mut scan_request = (**request).clone();
        scan_request.target = Some(target.to_string());
        Scanner::new(scan_request)
    }

    /// Filter results based on certificate validation filters
    ///
    /// Returns true if the scan result should be included in output.
    /// If no certificate filters are active, all results pass.
    /// If filters are active, only results matching the filter criteria pass.
    fn should_include_result(filters: &CertificateFilters, scan_result: &ScanResults) -> bool {
        // If no certificate filters are active, include everything
        if !filters.has_filters() {
            return true;
        }

        // Check if certificate analysis exists
        let cert_analysis = match &scan_result.certificate_chain {
            Some(analysis) => analysis,
            None => return false, // No certificate data, filter out
        };

        // Get certificate info and validation result
        let cert = match cert_analysis.chain.leaf() {
            Some(c) => c,
            None => return false, // No leaf certificate, filter out
        };

        // Extract hostname from target (format: "hostname:port")
        let hostname = split_target_host_port(&scan_result.target)
            .map(|(hostname, _)| hostname)
            .unwrap_or_else(|_| scan_result.target.clone());

        // Create certificate status
        let cert_status = CertificateStatus::from_validation_result(
            &cert_analysis.validation,
            &hostname,
            cert,
            cert_analysis.revocation.as_ref(),
        );

        // Check if status matches any active filters
        cert_status.matches_filter(filters)
    }

    /// Filter a collection of scan results based on certificate filters
    ///
    /// Returns only the results that match the active certificate filters.
    /// If no filters are active, returns all results.
    pub fn filter_results(
        filters: &CertificateFilters,
        results: Vec<(String, Result<ScanResults>)>,
    ) -> Vec<(String, Result<ScanResults>)> {
        // If no certificate filters are active, return all results
        if !filters.has_filters() {
            return results;
        }

        // Filter results based on certificate status
        results
            .into_iter()
            .filter(|(_, result)| {
                match result {
                    Ok(scan_result) => Self::should_include_result(filters, scan_result),
                    Err(_) => false, // Filter out failed scans when filters are active
                }
            })
            .collect()
    }

    /// Generate summary report
    pub fn generate_summary(results: &[(String, Result<ScanResults>)]) -> String {
        let total = results.len();
        let successful = results.iter().filter(|(_, r)| r.is_ok()).count();
        let failed = total - successful;

        let mut summary = Self::format_summary_header(total, successful, failed);
        summary.push_str(&Self::format_grade_distribution(results));
        summary.push_str(&Self::format_individual_results(results));
        summary.push_str(&"=".repeat(80));
        summary.push('\n');
        summary
    }

    fn format_summary_header(total: usize, successful: usize, failed: usize) -> String {
        let mut header = String::new();
        header.push('\n');
        header.push_str(&"=".repeat(80));
        header.push_str(&format!("\n{}\n", "MASS SCAN SUMMARY".cyan().bold()));
        header.push_str(&"=".repeat(80));
        header.push_str("\n\n");
        header.push_str(&format!(
            "{}: {} | {}: {} | {}: {}\n\n",
            "Total".bold(),
            total,
            "Successful".green().bold(),
            successful,
            "Failed".red().bold(),
            failed
        ));
        header
    }

    fn format_grade_distribution(results: &[(String, Result<ScanResults>)]) -> String {
        let mut grade_counts = std::collections::HashMap::new();
        for (_, result) in results {
            if let Ok(scan_result) = result
                && let Some(rating) = scan_result.ssl_rating()
            {
                *grade_counts.entry(format!("{}", rating.grade)).or_insert(0) += 1;
            }
        }

        if grade_counts.is_empty() {
            return String::new();
        }

        let mut section = format!("{}\n", "SSL Labs Grade Distribution:".bold());
        let mut grades: Vec<_> = grade_counts.iter().collect();
        grades.sort_by(|a, b| b.1.cmp(a.1));
        for (grade, count) in grades {
            section.push_str(&format!("  {}: {}\n", grade, count));
        }
        section.push('\n');
        section
    }

    fn format_individual_results(results: &[(String, Result<ScanResults>)]) -> String {
        let mut section = format!("{}\n", "Individual Results:".bold());
        section.push_str(&"-".repeat(80));
        section.push('\n');

        for (target, result) in results {
            match result {
                Ok(scan_result) => {
                    let grade = scan_result
                        .ssl_rating()
                        .map(|r| format!("{}", r.grade))
                        .unwrap_or_else(|| "N/A".to_string());

                    let cert_status = scan_result
                        .certificate_chain
                        .as_ref()
                        .map(|c| {
                            if c.validation.valid {
                                "OK".green()
                            } else {
                                "INVALID".red()
                            }
                        })
                        .unwrap_or_else(|| "?".yellow());

                    let vuln_count = scan_result
                        .vulnerabilities
                        .iter()
                        .filter(|v| v.vulnerable)
                        .count();

                    section.push_str(&format!(
                        "{:<40} | Grade: {:<4} | Cert: {} | Vulns: {}\n",
                        target.green(),
                        grade,
                        cert_status,
                        if vuln_count > 0 {
                            vuln_count.to_string().red()
                        } else {
                            vuln_count.to_string().green()
                        }
                    ));
                }
                Err(e) => {
                    section.push_str(&format!(
                        "{:<40} | {}: {}\n",
                        target.red(),
                        "ERROR".red().bold(),
                        e
                    ));
                }
            }
        }

        section
    }

    /// Export all results to JSON
    pub fn export_all_json(
        results: &[(String, Result<ScanResults>)],
        file_path: &str,
        pretty: bool,
    ) -> Result<()> {
        use serde_json::json;

        let json_results: Vec<_> = results
            .iter()
            .map(|(target, result)| {
                json!({
                    "target": target,
                    "success": result.is_ok(),
                    "results": result.as_ref().ok(),
                    "error": result.as_ref().err().map(|e| e.to_string()),
                })
            })
            .collect();

        let json_data = json!({
            "scan_type": "mass_scan",
            "total_targets": results.len(),
            "successful_scans": results.iter().filter(|(_, r)| r.is_ok()).count(),
            "failed_scans": results.iter().filter(|(_, r)| r.is_err()).count(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "results": json_results,
        });

        let json_string = if pretty {
            serde_json::to_string_pretty(&json_data)?
        } else {
            serde_json::to_string(&json_data)?
        };

        std::fs::write(file_path, json_string)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ScanRequest;
    use crate::rating::grader::Grade;
    use crate::rating::scoring::RatingResult;
    use crate::scanner::RatingResults;
    use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};
    use tempfile::tempdir;

    fn build_scan_with_expired_cert(expired: bool) -> ScanResults {
        use crate::certificates::parser::{CertificateChain, CertificateInfo};
        use crate::certificates::validator::ValidationResult;

        let mut validation = ValidationResult {
            valid: false,
            issues: Vec::new(),
            trust_chain_valid: false,
            hostname_match: true,
            not_expired: !expired,
            signature_valid: false,
            trusted_ca: None,
            platform_trust: None,
        };
        if expired {
            validation.not_expired = false;
        }

        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Example CA".to_string(),
            ..Default::default()
        };
        let chain = CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 0,
        };

        ScanResults {
            target: "example.com:443".to_string(),
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain,
                validation,
                revocation: None,
            }),
            ..Default::default()
        }
    }

    fn build_scan_with_rating(grade: Grade, score: u8, valid_cert: bool) -> ScanResults {
        use crate::certificates::parser::{CertificateChain, CertificateInfo};
        use crate::certificates::validator::ValidationResult;

        let validation = ValidationResult {
            valid: valid_cert,
            issues: Vec::new(),
            trust_chain_valid: valid_cert,
            hostname_match: true,
            not_expired: true,
            signature_valid: valid_cert,
            trusted_ca: None,
            platform_trust: None,
        };
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Example CA".to_string(),
            ..Default::default()
        };
        let chain = CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 0,
        };

        let rating = RatingResult {
            grade,
            score,
            certificate_score: score,
            protocol_score: score,
            key_exchange_score: score,
            cipher_strength_score: score,
            warnings: Vec::new(),
        };

        ScanResults {
            target: "example.com:443".to_string(),
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain,
                validation,
                revocation: None,
            }),
            rating: Some(RatingResults {
                ssl_rating: Some(rating),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_mass_scanner_creation() {
        let mut request = ScanRequest::default();
        request.scan.scope.all = true;
        let targets = vec!["example.com:443".to_string(), "google.com:443".to_string()];
        let scanner = MassScanner::new(request, MassScanConfig::default(), targets);
        assert_eq!(scanner.targets.len(), 2);
    }

    #[test]
    fn test_mass_scanner_from_file_parses_targets() {
        let mut path = std::env::temp_dir();
        path.push("cipherrun_targets.txt");
        std::fs::write(
            &path,
            "example.com:443\n# comment\n\n  mail.example.com:25  \n",
        )
        .expect("test file should be created");

        let scanner = MassScanner::from_file(
            ScanRequest::default(),
            MassScanConfig::default(),
            path.to_str().expect("test path should be valid UTF-8"),
        )
        .expect("should parse targets");
        assert_eq!(scanner.targets.len(), 2);
        assert_eq!(scanner.targets[0], "example.com:443");
        assert_eq!(scanner.targets[1], "mail.example.com:25");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_mass_scanner_from_file_empty_fails() {
        let mut path = std::env::temp_dir();
        path.push("cipherrun_targets_empty.txt");
        std::fs::write(&path, "  \n# only comment\n").expect("test file should be created");

        let err = MassScanner::from_file(
            ScanRequest::default(),
            MassScanConfig::default(),
            path.to_str().expect("test path should be valid UTF-8"),
        )
        .err()
        .expect("result should be an error");
        let msg = err.to_string();
        assert!(msg.contains("No targets found"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_filter_results_no_filters_returns_all() {
        let filters = CertificateFilters::default();
        let results = vec![
            ("one".to_string(), Ok(ScanResults::default())),
            (
                "two".to_string(),
                Err(crate::error::TlsError::Other("fail".to_string())),
            ),
        ];
        let filtered = MassScanner::filter_results(&filters, results);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_results_expired_only() {
        let filters = CertificateFilters {
            expired: true,
            ..Default::default()
        };

        let results = vec![
            (
                "expired".to_string(),
                Ok(build_scan_with_expired_cert(true)),
            ),
            ("valid".to_string(), Ok(build_scan_with_expired_cert(false))),
            (
                "error".to_string(),
                Err(crate::error::TlsError::Other("fail".to_string())),
            ),
        ];
        let filtered = MassScanner::filter_results(&filters, results);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "expired");
    }

    #[test]
    fn test_filter_results_with_missing_certificate_chain() {
        let filters = CertificateFilters {
            expired: true,
            ..Default::default()
        };

        let results = vec![("no-cert".to_string(), Ok(ScanResults::default()))];
        let filtered = MassScanner::filter_results(&filters, results);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_create_scanner_sets_target_and_quiet() {
        let request = Arc::new(ScanRequest {
            scan: crate::application::scan_request::ScanRequestScan {
                prefs: crate::application::scan_request::ScanRequestPrefs {
                    probe_status: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        });
        let scanner =
            MassScanner::create_scanner(&request, "example.com:443").expect("should build scanner");
        assert_eq!(scanner.request.target.as_deref(), Some("example.com:443"));
    }

    #[test]
    fn test_generate_summary_includes_grades_and_errors() {
        let mut ok_scan = build_scan_with_rating(Grade::A, 90, true);
        ok_scan.vulnerabilities.push(VulnerabilityResult {
            vuln_type: VulnerabilityType::ROBOT,
            vulnerable: true,
            inconclusive: false,
            details: "Detected".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::High,
        });

        let results = vec![
            ("ok.example:443".to_string(), Ok(ok_scan)),
            (
                "fail.example:443".to_string(),
                Err(crate::error::TlsError::Other("fail".to_string())),
            ),
            (
                "ok2.example:443".to_string(),
                Ok(build_scan_with_rating(Grade::B, 80, false)),
            ),
        ];

        let summary = MassScanner::generate_summary(&results);
        assert!(summary.contains("MASS SCAN SUMMARY"));
        assert!(summary.contains("Grade Distribution"));
        assert!(summary.contains("ERROR"));
        assert!(summary.contains("Vulns"));
    }

    #[test]
    fn test_export_all_json_writes_file() {
        let dir = tempdir().expect("test assertion should succeed");
        let path = dir.path().join("mass_scan.json");

        let results = vec![("example.com:443".to_string(), Ok(ScanResults::default()))];
        MassScanner::export_all_json(
            &results,
            path.to_str().expect("test path should be valid UTF-8"),
            true,
        )
        .expect("test assertion should succeed");

        let contents = std::fs::read_to_string(&path).expect("test assertion should succeed");
        assert!(contents.contains("\"scan_type\""));
        assert!(contents.contains("\"mass_scan\""));
    }

    #[test]
    fn test_from_file_with_only_comments_returns_error() {
        let dir = tempdir().expect("test assertion should succeed");
        let path = dir.path().join("targets.txt");
        std::fs::write(&path, "# comment only\n\n   \n").expect("test file should be created");

        let err = MassScanner::from_file(
            ScanRequest::default(),
            MassScanConfig::default(),
            path.to_str().expect("test path should be valid UTF-8"),
        )
        .err()
        .expect("result should be an error");
        assert!(err.to_string().contains("No targets found"));
    }
}
