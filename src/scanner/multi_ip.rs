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

#[path = "multi_ip/progress.rs"]
mod progress;

pub use progress::{
    IpScanProgress, MultiIpProgressCallback, MultiIpScanSummary, SilentMultiIpProgress,
    TerminalMultiIpProgress,
};

use crate::Result;
use crate::application::ScanRequest;
use crate::scanner::aggregation::{AggregatedScanResult, ConservativeAggregator};
use crate::scanner::inconsistency::{Inconsistency, InconsistencyDetector};
use crate::scanner::{ScanResults, Scanner};
use crate::utils::network::Target;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Multi-IP scanner that scans multiple IP addresses in parallel
pub struct MultiIpScanner {
    pub target: Target,
    pub request: ScanRequest,
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
    #[serde(serialize_with = "crate::scanner::results::serialize_sorted_map")]
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
    pub fn new(target: Target, request: ScanRequest) -> Self {
        Self {
            target,
            request,
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

        // Performance optimization: Use Arc to avoid cloning Target and request for each scan
        let target_arc = Arc::new(self.target.clone());
        let request_arc = Arc::new(self.request.clone());
        let callback_arc = self.callback.clone();

        // Create futures for each IP (without spawning)
        for (index, ip) in self.target.ip_addresses.iter().enumerate() {
            let sem = Arc::clone(&semaphore);
            let ip = *ip;
            let target = Arc::clone(&target_arc);
            let request = Arc::clone(&request_arc);
            let callback = callback_arc.clone();
            let total = total_ips;
            let task_index = index + 1;

            // Create an async block future (no tokio::spawn)
            let future = async move {
                // Acquire semaphore permit - use proper error handling instead of expect()
                let _permit = match sem.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Semaphore was closed - return error result
                        return SingleIpScanResult {
                            ip,
                            scan_result: ScanResults::default(),
                            scan_duration_ms: 0,
                            error: Some("Scanner semaphore closed - scan aborted".to_string()),
                        };
                    }
                };

                // Notify callback of IP scan start
                if let Some(ref cb) = callback {
                    cb.on_ip_start(&ip.to_string(), task_index, total);
                }

                // Scan this IP (dereference Arc to pass owned values)
                let result = Self::scan_single_ip(ip, (*target).clone(), (*request).clone()).await;

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
            if per_ip_results.contains_key(&result.ip) {
                tracing::warn!(
                    "Duplicate IP result for {}, overwriting previous result",
                    result.ip
                );
            }
            per_ip_results.insert(result.ip, result);
        }

        let total_duration_ms = total_start.elapsed().as_millis() as u64;
        let successful_scans = per_ip_results
            .values()
            .filter(|r| r.error.is_none())
            .count();
        let failed_scans = per_ip_results.len().saturating_sub(successful_scans);

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
    async fn scan_single_ip(
        ip: IpAddr,
        target: Target,
        request: ScanRequest,
    ) -> SingleIpScanResult {
        let start = Instant::now();

        // Create a target specific for this IP
        let mut ip_target = target;
        ip_target.ip_addresses = vec![ip];

        // Create scanner for this IP
        let scanner = match Scanner::new(request) {
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
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
            inconsistencies: Vec::new(),
        };

        assert_eq!(report.successful_results().len(), 1);
        assert_eq!(report.failed_results().len(), 0);
        assert_eq!(report.avg_scan_duration_ms(), Some(1000));
    }

    #[test]
    fn test_multi_ip_report_with_failures() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![
                "93.184.216.34".parse().unwrap(),
                "93.184.216.35".parse().unwrap(),
            ],
        )
        .unwrap();

        let mut per_ip_results = HashMap::new();
        per_ip_results.insert(
            "93.184.216.34".parse().unwrap(),
            SingleIpScanResult {
                ip: "93.184.216.34".parse().unwrap(),
                scan_result: ScanResults::default(),
                scan_duration_ms: 1200,
                error: None,
            },
        );
        per_ip_results.insert(
            "93.184.216.35".parse().unwrap(),
            SingleIpScanResult {
                ip: "93.184.216.35".parse().unwrap(),
                scan_result: ScanResults::default(),
                scan_duration_ms: 800,
                error: Some("timeout".to_string()),
            },
        );

        let report = MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 2,
            successful_scans: 1,
            failed_scans: 1,
            total_duration_ms: 2000,
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
            inconsistencies: Vec::new(),
        };

        assert_eq!(report.successful_results().len(), 1);
        assert_eq!(report.failed_results().len(), 1);
        assert_eq!(report.avg_scan_duration_ms(), Some(1200));
    }

    #[test]
    fn test_terminal_progress_callbacks() {
        let progress = TerminalMultiIpProgress::new();

        progress.on_scan_start(2);
        progress.on_ip_start("127.0.0.1", 1, 2);

        let ok = IpScanProgress {
            ip: "127.0.0.1",
            index: 1,
            total: 2,
            success: true,
            duration_secs: 0.5,
            error: None,
        };
        progress.on_ip_complete(&ok);

        let failed = IpScanProgress {
            ip: "127.0.0.2",
            index: 2,
            total: 2,
            success: false,
            duration_secs: 1.2,
            error: Some("timeout"),
        };
        progress.on_ip_complete(&failed);

        let summary_ok = MultiIpScanSummary {
            total_ips: 1,
            successful: 1,
            failed: 0,
            duration_secs: 1.0,
            failed_results: &[],
        };
        progress.on_scan_summary(&summary_ok);

        let failed_results: Vec<(IpAddr, String)> =
            vec![("127.0.0.2".parse().unwrap(), "timeout".to_string())];
        let summary_warn = MultiIpScanSummary {
            total_ips: 2,
            successful: 1,
            failed: 1,
            duration_secs: 2.0,
            failed_results: &failed_results,
        };
        progress.on_scan_summary(&summary_warn);

        progress.on_consistency_analysis_start();
        progress.on_consistency_analysis_complete(&[]);
        progress.on_aggregation_start();
    }

    #[test]
    fn test_avg_scan_duration_none_when_no_success() {
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
                scan_duration_ms: 1200,
                error: Some("failed".to_string()),
            },
        );

        let report = MultiIpScanReport {
            target,
            per_ip_results,
            total_ips: 1,
            successful_scans: 0,
            failed_scans: 1,
            total_duration_ms: 1200,
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
            inconsistencies: Vec::new(),
        };

        assert_eq!(report.avg_scan_duration_ms(), None);
    }

    #[test]
    fn test_multi_ip_scanner_sets_callback() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let request = ScanRequest::default();

        let scanner = MultiIpScanner::new(target, request).with_terminal_progress();
        assert!(scanner.callback.is_some());
    }
}
