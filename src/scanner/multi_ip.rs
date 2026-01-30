// Multi-IP Scanner - Parallel scanning of multiple IP addresses
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0
//
// This module implements parallel scanning of multiple IP addresses for the same hostname,
// which is essential for testing Anycast deployments, load-balanced servers, and CDNs.
//
// Phase 3 additions:
// - Inconsistency detection across backends
// - Conservative aggregation of results
// - Detailed reporting with per-IP breakdowns

use crate::Args;
use crate::Result;
use crate::scanner::aggregation::{AggregatedScanResult, ConservativeAggregator};
use crate::scanner::inconsistency::{Inconsistency, InconsistencyDetector};
use crate::scanner::{ScanResults, Scanner};
use crate::utils::network::Target;
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Progress information for a completed IP scan
#[derive(Debug, Clone)]
pub struct IpScanProgress<'a> {
    pub ip: &'a str,
    pub index: usize,
    pub total: usize,
    pub success: bool,
    pub duration_secs: f64,
    pub error: Option<&'a str>,
}

/// Summary of a multi-IP scan operation
#[derive(Debug, Clone)]
pub struct MultiIpScanSummary<'a> {
    pub total_ips: usize,
    pub successful: usize,
    pub failed: usize,
    pub duration_secs: f64,
    pub failed_results: &'a [(IpAddr, String)],
}

/// Callback trait for multi-IP scan progress reporting.
///
/// Implement this trait to receive progress updates during multi-IP scanning.
/// The default implementation `TerminalMultiIpProgress` provides colored terminal output.
pub trait MultiIpProgressCallback: Send + Sync {
    /// Called when the scan starts
    fn on_scan_start(&self, total_ips: usize);

    /// Called when scanning of an individual IP begins
    fn on_ip_start(&self, ip: &str, index: usize, total: usize);

    /// Called when scanning of an individual IP completes
    fn on_ip_complete(&self, progress: &IpScanProgress<'_>);

    /// Called after all IPs are scanned with summary information
    fn on_scan_summary(&self, summary: &MultiIpScanSummary<'_>);

    /// Called when consistency analysis begins
    fn on_consistency_analysis_start(&self);

    /// Called when consistency analysis completes
    fn on_consistency_analysis_complete(&self, inconsistencies: &[Inconsistency]);

    /// Called when aggregation begins
    fn on_aggregation_start(&self);
}

/// Default terminal progress callback with colored output
pub struct TerminalMultiIpProgress;

impl TerminalMultiIpProgress {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalMultiIpProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiIpProgressCallback for TerminalMultiIpProgress {
    fn on_scan_start(&self, total_ips: usize) {
        println!(
            "Scanning {} IP address{} in parallel...\n",
            total_ips.to_string().cyan().bold(),
            if total_ips == 1 { "" } else { "es" }
        );
    }

    fn on_ip_start(&self, ip: &str, index: usize, total: usize) {
        println!(
            "[{}/{}] {} - Scanning...",
            index.to_string().cyan(),
            total,
            ip.yellow()
        );
    }

    fn on_ip_complete(&self, progress: &IpScanProgress<'_>) {
        if progress.success {
            println!(
                "[{}/{}] {} - {} Complete ({:.1}s)",
                progress.index.to_string().cyan(),
                progress.total,
                progress.ip.yellow(),
                "✓".green(),
                progress.duration_secs
            );
        } else {
            println!(
                "[{}/{}] {} - {} Failed: {}",
                progress.index.to_string().cyan(),
                progress.total,
                progress.ip.yellow(),
                "✗".red(),
                progress.error.unwrap_or("Unknown error").red()
            );
        }
    }

    fn on_scan_summary(&self, summary: &MultiIpScanSummary<'_>) {
        println!();
        if summary.failed == 0 {
            println!(
                "{} All IPs scanned successfully in {:.1}s",
                "✓".green().bold(),
                summary.duration_secs
            );
        } else {
            println!(
                "{} {}/{} IPs scanned successfully in {:.1}s",
                "⚠".yellow().bold(),
                summary.successful,
                summary.total_ips,
                summary.duration_secs
            );
            println!(
                "  {} {} of {} IPs failed to scan:",
                "⚠".yellow(),
                summary.failed,
                summary.total_ips
            );
            for (ip, err) in summary.failed_results {
                println!("    {} {}", ip.to_string().yellow(), err.red());
            }
        }
    }

    fn on_consistency_analysis_start(&self) {
        println!("\nAnalyzing configuration consistency across backends...");
    }

    fn on_consistency_analysis_complete(&self, inconsistencies: &[Inconsistency]) {
        if !inconsistencies.is_empty() {
            println!(
                "{} {} configuration inconsistenc{} detected",
                "⚠".yellow().bold(),
                inconsistencies.len(),
                if inconsistencies.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            );
        } else {
            println!(
                "{} All backends have consistent configuration",
                "✓".green().bold()
            );
        }
    }

    fn on_aggregation_start(&self) {
        println!("Aggregating results (conservative worst-case approach)...");
    }
}

/// Silent progress callback that produces no output
pub struct SilentMultiIpProgress;

impl MultiIpProgressCallback for SilentMultiIpProgress {
    fn on_scan_start(&self, _total_ips: usize) {}
    fn on_ip_start(&self, _ip: &str, _index: usize, _total: usize) {}
    fn on_ip_complete(&self, _progress: &IpScanProgress<'_>) {}
    fn on_scan_summary(&self, _summary: &MultiIpScanSummary<'_>) {}
    fn on_consistency_analysis_start(&self) {}
    fn on_consistency_analysis_complete(&self, _inconsistencies: &[Inconsistency]) {}
    fn on_aggregation_start(&self) {}
}

/// Multi-IP scanner that scans multiple IP addresses in parallel
pub struct MultiIpScanner {
    pub target: Target,
    pub args: Args,
    pub max_concurrent_scans: usize,
    callback: Option<Arc<dyn MultiIpProgressCallback>>,
}

/// Result from scanning a single IP address
///
/// Note: This is re-exported from scanner::inconsistency for public API compatibility
pub type SingleIpScanResult = crate::scanner::inconsistency::SingleIpScanResult;

/// Report containing results from all IP addresses with inconsistency detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiIpScanReport {
    pub target: Target,
    pub per_ip_results: HashMap<IpAddr, SingleIpScanResult>,
    pub total_ips: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub total_duration_ms: u64,

    // Phase 3 additions
    pub inconsistencies: Vec<Inconsistency>,
    pub aggregated: AggregatedScanResult,
}

impl MultiIpScanner {
    /// Create a new multi-IP scanner
    pub fn new(target: Target, args: Args) -> Self {
        Self {
            target,
            args,
            max_concurrent_scans: 4, // Default to 4 concurrent scans
            callback: None,
        }
    }

    /// Set maximum concurrent scans
    pub fn with_max_concurrent(mut self, max_concurrent: usize) -> Self {
        self.max_concurrent_scans = max_concurrent;
        self
    }

    /// Set progress callback for receiving scan updates
    pub fn with_callback(mut self, callback: Arc<dyn MultiIpProgressCallback>) -> Self {
        self.callback = Some(callback);
        self
    }

    /// Set terminal progress callback (convenience method)
    pub fn with_terminal_progress(self) -> Self {
        self.with_callback(Arc::new(TerminalMultiIpProgress::new()))
    }

    /// Scan all IP addresses in parallel with inconsistency detection
    pub async fn scan_all_ips(&self) -> Result<MultiIpScanReport> {
        let total_start = Instant::now();
        let total_ips = self.target.ip_addresses.len();

        // Notify callback of scan start
        if let Some(ref callback) = self.callback {
            callback.on_scan_start(total_ips);
        }

        // Create semaphore to limit concurrency
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_scans));
        let mut futures = FuturesUnordered::new();

        // Performance optimization: Use Arc to avoid cloning Target and Args for each scan
        let target_arc = Arc::new(self.target.clone());
        let args_arc = Arc::new(self.args.clone());
        let callback_arc = self.callback.clone();

        // Create futures for each IP (without spawning)
        for (index, ip) in self.target.ip_addresses.iter().enumerate() {
            let sem = Arc::clone(&semaphore);
            let ip = *ip;
            let target = Arc::clone(&target_arc);
            let args = Arc::clone(&args_arc);
            let callback = callback_arc.clone();
            let total = total_ips;
            let task_index = index + 1;

            // Create an async block future (no tokio::spawn)
            let future = async move {
                // Acquire semaphore permit
                let _permit = sem.acquire().await.expect("semaphore closed");

                // Notify callback of IP scan start
                if let Some(ref cb) = callback {
                    cb.on_ip_start(&ip.to_string(), task_index, total);
                }

                // Scan this IP (dereference Arc to pass owned values)
                let result = Self::scan_single_ip(ip, (*target).clone(), (*args).clone()).await;

                // Notify callback of IP scan completion
                if let Some(ref cb) = callback {
                    let ip_str = ip.to_string();
                    let progress = IpScanProgress {
                        ip: &ip_str,
                        index: task_index,
                        total,
                        success: result.error.is_none(),
                        duration_secs: result.scan_duration_ms as f64 / 1000.0,
                        error: result.error.as_deref(),
                    };
                    cb.on_ip_complete(&progress);
                }

                result
            };

            futures.push(future);
        }

        // Wait for all futures to complete
        let mut per_ip_results = HashMap::new();
        while let Some(result) = futures.next().await {
            per_ip_results.insert(result.ip, result);
        }

        let total_duration_ms = total_start.elapsed().as_millis() as u64;
        let successful_scans = per_ip_results
            .values()
            .filter(|r| r.error.is_none())
            .count();
        let failed_scans = total_ips - successful_scans;

        // Notify callback of scan summary
        if let Some(ref callback) = self.callback {
            let failed_results: Vec<(IpAddr, String)> = per_ip_results
                .values()
                .filter_map(|r| r.error.as_ref().map(|err| (r.ip, err.clone())))
                .collect();
            let summary = MultiIpScanSummary {
                total_ips,
                successful: successful_scans,
                failed: failed_scans,
                duration_secs: total_duration_ms as f64 / 1000.0,
                failed_results: &failed_results,
            };
            callback.on_scan_summary(&summary);
        }

        // Phase 3: Detect inconsistencies
        if let Some(ref callback) = self.callback {
            callback.on_consistency_analysis_start();
        }
        let detector = InconsistencyDetector::new(per_ip_results.clone());
        let inconsistencies = detector.detect_all();

        if let Some(ref callback) = self.callback {
            callback.on_consistency_analysis_complete(&inconsistencies);
        }

        // Phase 3: Perform conservative aggregation
        if let Some(ref callback) = self.callback {
            callback.on_aggregation_start();
        }
        let aggregator =
            ConservativeAggregator::new(per_ip_results.clone(), inconsistencies.clone());
        let aggregated = aggregator.aggregate();

        Ok(MultiIpScanReport {
            target: self.target.clone(),
            per_ip_results,
            total_ips,
            successful_scans,
            failed_scans,
            total_duration_ms,
            inconsistencies,
            aggregated,
        })
    }

    /// Scan a single IP address
    async fn scan_single_ip(ip: IpAddr, target: Target, args: Args) -> SingleIpScanResult {
        let start = Instant::now();

        // Create a target specific for this IP
        let mut ip_target = target;
        ip_target.ip_addresses = vec![ip];

        // Create scanner for this IP
        let scanner = match Scanner::new(args) {
            Ok(scanner) => scanner,
            Err(e) => {
                return SingleIpScanResult {
                    ip,
                    scan_result: ScanResults::default(),
                    scan_duration_ms: start.elapsed().as_millis() as u64,
                    error: Some(format!("Failed to create scanner: {}", e)),
                };
            }
        };

        // Override the target with our single-IP target
        scanner.set_target(ip_target);

        // Run the scan
        match scanner.run().await {
            Ok(scan_result) => SingleIpScanResult {
                ip,
                scan_result,
                scan_duration_ms: start.elapsed().as_millis() as u64,
                error: None,
            },
            Err(e) => SingleIpScanResult {
                ip,
                scan_result: ScanResults::default(),
                scan_duration_ms: start.elapsed().as_millis() as u64,
                error: Some(e.to_string()),
            },
        }
    }
}

impl MultiIpScanReport {
    /// Get successful scan results
    pub fn successful_results(&self) -> Vec<&SingleIpScanResult> {
        self.per_ip_results
            .values()
            .filter(|r| r.error.is_none())
            .collect()
    }

    /// Get failed scan results
    pub fn failed_results(&self) -> Vec<&SingleIpScanResult> {
        self.per_ip_results
            .values()
            .filter(|r| r.error.is_some())
            .collect()
    }

    /// Get average scan duration for successful scans
    pub fn avg_scan_duration_ms(&self) -> Option<u64> {
        let successful: Vec<_> = self.successful_results();
        if successful.is_empty() {
            return None;
        }

        let total: u64 = successful.iter().map(|r| r.scan_duration_ms).sum();
        Some(total / successful.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_ip_report_successful_results() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let mut per_ip_results = HashMap::new();
        per_ip_results.insert(
            "93.184.216.34".parse().unwrap(),
            SingleIpScanResult {
                ip: "93.184.216.34".parse().unwrap(),
                scan_result: ScanResults::default(),
                scan_duration_ms: 1000,
                error: None,
            },
        );

        let report = MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 1,
            successful_scans: 1,
            failed_scans: 0,
            total_duration_ms: 1000,
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("F".to_string(), 0),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: false,
                session_resumption_tickets: false,
            },
            inconsistencies: Vec::new(),
        };

        assert_eq!(report.successful_results().len(), 1);
        assert_eq!(report.failed_results().len(), 0);
        assert_eq!(report.avg_scan_duration_ms(), Some(1000));
    }
}
