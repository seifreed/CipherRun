// Mass Scanner - Parallel and serial scanning of multiple targets

use crate::Args;
use crate::Result;
use crate::certificates::status::CertificateStatus;
use crate::scanner::{ScanResults, Scanner};
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Progress information for a completed target scan
#[derive(Debug)]
pub struct TargetScanProgress<'a> {
    pub target: &'a str,
    pub index: usize,
    pub total: usize,
    pub result: &'a Result<ScanResults>,
    pub duration: Duration,
}

/// Callback trait for mass scan progress reporting.
///
/// Implement this trait to receive progress updates during mass scanning.
/// The default implementation `TerminalMassProgress` provides colored terminal output.
pub trait MassScanProgressCallback: Send + Sync {
    /// Called when serial scanning starts
    fn on_serial_scan_start(&self, total_targets: usize);

    /// Called when parallel scanning starts
    fn on_parallel_scan_start(&self, total_targets: usize, max_concurrent: usize);

    /// Called when scanning of an individual target begins
    fn on_target_start(&self, target: &str, index: usize, total: usize);

    /// Called when scanning of an individual target completes
    fn on_target_complete(&self, progress: &TargetScanProgress<'_>);

    /// Called periodically during parallel scanning to update progress
    fn on_parallel_progress(&self, completed: usize, total: usize, current_target: &str);

    /// Called when all scans are complete
    fn on_all_scans_complete(&self);
}

/// Default terminal progress callback with colored output
pub struct TerminalMassProgress;

impl TerminalMassProgress {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalMassProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl MassScanProgressCallback for TerminalMassProgress {
    fn on_serial_scan_start(&self, total_targets: usize) {
        println!(
            "\n{} {} targets serially...\n",
            "Scanning".cyan().bold(),
            total_targets
        );
    }

    fn on_parallel_scan_start(&self, total_targets: usize, max_concurrent: usize) {
        println!(
            "\n{} {} targets in parallel (max {} concurrent)...\n",
            "Scanning".cyan().bold(),
            total_targets,
            max_concurrent
        );
    }

    fn on_target_start(&self, target: &str, index: usize, total: usize) {
        println!(
            "{} Scanning {}/{}: {}",
            "[+]".green(),
            index,
            total,
            target.yellow()
        );
    }

    fn on_target_complete(&self, progress: &TargetScanProgress<'_>) {
        match progress.result {
            Ok(scan_results) => {
                println!(
                    "  {} Scan completed in {:.2}s",
                    "OK".green(),
                    progress.duration.as_secs_f64()
                );
                if let Some(rating) = scan_results.ssl_rating() {
                    println!("  {} SSL Labs Grade: {}", "INFO".blue(), rating.grade);
                }
            }
            Err(e) => {
                println!("  {} Scan failed: {}", "ERR".red(), e);
            }
        }
        println!();
    }

    fn on_parallel_progress(&self, _completed: usize, _total: usize, _current_target: &str) {
        // Progress bar handles this in terminal mode
    }

    fn on_all_scans_complete(&self) {
        // Progress bar handles this in terminal mode
    }
}

/// Silent progress callback that produces no output
pub struct SilentMassProgress;

impl MassScanProgressCallback for SilentMassProgress {
    fn on_serial_scan_start(&self, _total_targets: usize) {}
    fn on_parallel_scan_start(&self, _total_targets: usize, _max_concurrent: usize) {}
    fn on_target_start(&self, _target: &str, _index: usize, _total: usize) {}
    fn on_target_complete(&self, _progress: &TargetScanProgress<'_>) {}
    fn on_parallel_progress(&self, _completed: usize, _total: usize, _current_target: &str) {}
    fn on_all_scans_complete(&self) {}
}

/// Mass scanner for scanning multiple targets
///
/// Performance optimization: Uses Arc<Args> to avoid expensive cloning
/// in parallel scanning operations.
pub struct MassScanner {
    args: Arc<Args>,
    pub targets: Vec<String>,
    callback: Option<Arc<dyn MassScanProgressCallback>>,
}

impl MassScanner {
    /// Create a new mass scanner
    pub fn new(args: Args, targets: Vec<String>) -> Self {
        Self {
            args: Arc::new(args),
            targets,
            callback: None,
        }
    }

    /// Load targets from file
    pub fn from_file(args: Args, file_path: &str) -> Result<Self> {
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
            args: Arc::new(args),
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
        let max_parallel = self.args.network.max_parallel;
        let total = self.targets.len();

        // Notify callback of scan start
        if let Some(ref callback) = self.callback {
            callback.on_parallel_scan_start(total, max_parallel);
        }

        // Create progress bars
        let multi_progress = Arc::new(MultiProgress::new());
        let main_pb = multi_progress.add(ProgressBar::new(total as u64));
        main_pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                .expect("Invalid template")
                .progress_chars("=>-"),
        );

        // Create semaphore to limit concurrent scans
        let semaphore = Arc::new(Semaphore::new(max_parallel));

        // Spawn tasks for all targets
        let mut tasks = Vec::new();

        for target in &self.targets {
            let target = target.clone();
            let semaphore = Arc::clone(&semaphore);
            // Performance optimization: Use Arc::clone instead of expensive Args clone
            let args = Arc::clone(&self.args);
            let multi_progress = Arc::clone(&multi_progress);

            let task = tokio::spawn(async move {
                // Acquire semaphore permit - use expect since closed semaphore is fatal
                let _permit = semaphore
                    .acquire()
                    .await
                    .expect("Semaphore closed unexpectedly");

                // Create progress bar for this target
                let pb = multi_progress.add(ProgressBar::new_spinner());
                pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .expect("Invalid template"),
                );
                pb.set_message(format!("Scanning {}", target));

                // Perform scan
                let scanner = MassScanner::create_scanner(&args, &target);
                let result = match scanner {
                    Ok(s) => s.run().await,
                    Err(e) => Err(e),
                };

                pb.finish_and_clear();
                (target, result)
            });

            tasks.push(task);
        }

        // Collect results
        let mut results = Vec::new();
        for task in tasks {
            let (target, result) = task.await?;
            main_pb.inc(1);

            // Notify callback of progress
            if let Some(ref callback) = self.callback {
                callback.on_parallel_progress(results.len() + 1, total, &target);
            }

            main_pb.set_message(format!("Completed: {}", target));
            results.push((target, result));
        }

        main_pb.finish_with_message("All scans completed");

        // Notify callback of completion
        if let Some(ref callback) = self.callback {
            callback.on_all_scans_complete();
        }

        Ok(results)
    }

    /// Scan a single target
    async fn scan_single_target(&self, target: &str) -> Result<ScanResults> {
        let scanner = Self::create_scanner(&self.args, target)?;
        scanner.run().await
    }

    /// Create a scanner for a specific target
    ///
    /// Performance optimization: Takes Arc<Args> to avoid cloning
    fn create_scanner(args: &Arc<Args>, target: &str) -> Result<Scanner> {
        // Only clone when necessary to modify target and quiet flag
        let mut modified_args = (**args).clone();
        modified_args.target = Some(target.to_string());
        modified_args.output.quiet = true; // Suppress banner in mass scan
        Scanner::new(modified_args)
    }

    /// Filter results based on certificate validation filters
    ///
    /// Returns true if the scan result should be included in output.
    /// If no certificate filters are active, all results pass.
    /// If filters are active, only results matching the filter criteria pass.
    fn should_include_result(args: &Args, scan_result: &ScanResults) -> bool {
        // If no certificate filters are active, include everything
        if !args.has_certificate_filters() {
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
        let hostname = scan_result
            .target
            .split(':')
            .next()
            .unwrap_or(&scan_result.target);

        // Create certificate status
        let cert_status = CertificateStatus::from_validation_result(
            &cert_analysis.validation,
            hostname,
            cert,
            cert_analysis.revocation.as_ref(),
        );

        // Check if status matches any active filters
        cert_status.matches_filter(args)
    }

    /// Filter a collection of scan results based on certificate filters
    ///
    /// Returns only the results that match the active certificate filters.
    /// If no filters are active, returns all results.
    pub fn filter_results(
        args: &Args,
        results: Vec<(String, Result<ScanResults>)>,
    ) -> Vec<(String, Result<ScanResults>)> {
        // If no certificate filters are active, return all results
        if !args.has_certificate_filters() {
            return results;
        }

        // Filter results based on certificate status
        results
            .into_iter()
            .filter(|(_, result)| {
                match result {
                    Ok(scan_result) => Self::should_include_result(args, scan_result),
                    Err(_) => false, // Filter out failed scans when filters are active
                }
            })
            .collect()
    }

    /// Get reference to args (for external use)
    pub fn args(&self) -> &Args {
        &self.args
    }

    /// Generate summary report
    pub fn generate_summary(results: &[(String, Result<ScanResults>)]) -> String {
        let mut summary = String::new();
        summary.push('\n');
        summary.push_str(&"=".repeat(80));
        summary.push_str(&format!("\n{}\n", "MASS SCAN SUMMARY".cyan().bold()));
        summary.push_str(&"=".repeat(80));
        summary.push_str("\n\n");

        let total = results.len();
        let successful = results.iter().filter(|(_, r)| r.is_ok()).count();
        let failed = total - successful;

        summary.push_str(&format!(
            "{}: {} | {}: {} | {}: {}\n\n",
            "Total".bold(),
            total,
            "Successful".green().bold(),
            successful,
            "Failed".red().bold(),
            failed
        ));

        // Grade distribution
        let mut grade_counts = std::collections::HashMap::new();
        for (_, result) in results {
            if let Ok(scan_result) = result
                && let Some(rating) = scan_result.ssl_rating()
            {
                *grade_counts.entry(format!("{}", rating.grade)).or_insert(0) += 1;
            }
        }

        if !grade_counts.is_empty() {
            summary.push_str(&format!("{}\n", "SSL Labs Grade Distribution:".bold()));
            let mut grades: Vec<_> = grade_counts.iter().collect();
            grades.sort_by(|a, b| b.1.cmp(a.1));
            for (grade, count) in grades {
                summary.push_str(&format!("  {}: {}\n", grade, count));
            }
            summary.push('\n');
        }

        // Individual results
        summary.push_str(&format!("{}\n", "Individual Results:".bold()));
        summary.push_str(&"-".repeat(80));
        summary.push('\n');

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

                    summary.push_str(&format!(
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
                    summary.push_str(&format!(
                        "{:<40} | {}: {}\n",
                        target.red(),
                        "ERROR".red().bold(),
                        e
                    ));
                }
            }
        }

        summary.push_str(&"=".repeat(80));
        summary.push('\n');

        summary
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

    #[test]
    fn test_mass_scanner_creation() {
        let mut args = Args::default();
        args.scan.all = true;
        let targets = vec!["example.com:443".to_string(), "google.com:443".to_string()];
        let scanner = MassScanner::new(args, targets);
        assert_eq!(scanner.targets.len(), 2);
    }
}
