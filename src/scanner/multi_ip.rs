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

/// Multi-IP scanner that scans multiple IP addresses in parallel
pub struct MultiIpScanner {
    pub target: Target,
    pub args: Args,
    pub max_concurrent_scans: usize,
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
        }
    }

    /// Set maximum concurrent scans
    pub fn with_max_concurrent(mut self, max_concurrent: usize) -> Self {
        self.max_concurrent_scans = max_concurrent;
        self
    }

    /// Scan all IP addresses in parallel with inconsistency detection
    pub async fn scan_all_ips(&self) -> Result<MultiIpScanReport> {
        let total_start = Instant::now();
        let total_ips = self.target.ip_addresses.len();

        println!(
            "Scanning {} IP address{} in parallel...\n",
            total_ips.to_string().cyan().bold(),
            if total_ips == 1 { "" } else { "es" }
        );

        // Create semaphore to limit concurrency
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_scans));
        let mut futures = FuturesUnordered::new();

        // Create futures for each IP (without spawning)
        for (index, ip) in self.target.ip_addresses.iter().enumerate() {
            let sem = Arc::clone(&semaphore);
            let ip = *ip;
            let target = self.target.clone();
            let args = self.args.clone();
            let total = total_ips;
            let task_index = index + 1;

            // Create an async block future (no tokio::spawn)
            let future = async move {
                // Acquire semaphore permit
                let _permit = sem.acquire().await.expect("semaphore closed");

                // Display progress
                println!(
                    "[{}/{}] {} - Scanning...",
                    task_index.to_string().cyan(),
                    total,
                    ip.to_string().yellow()
                );

                // Scan this IP
                let result = Self::scan_single_ip(ip, target, args).await;

                // Display completion
                match &result.error {
                    None => println!(
                        "[{}/{}] {} - {} Complete ({:.1}s)",
                        task_index.to_string().cyan(),
                        total,
                        ip.to_string().yellow(),
                        "✓".green(),
                        result.scan_duration_ms as f64 / 1000.0
                    ),
                    Some(err) => println!(
                        "[{}/{}] {} - {} Failed: {}",
                        task_index.to_string().cyan(),
                        total,
                        ip.to_string().yellow(),
                        "✗".red(),
                        err.red()
                    ),
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

        // Display summary
        println!();
        if failed_scans == 0 {
            println!(
                "{} All IPs scanned successfully in {:.1}s",
                "✓".green().bold(),
                total_duration_ms as f64 / 1000.0
            );
        } else {
            println!(
                "{} {}/{} IPs scanned successfully in {:.1}s",
                "⚠".yellow().bold(),
                successful_scans,
                total_ips,
                total_duration_ms as f64 / 1000.0
            );
            println!(
                "  {} {} of {} IPs failed to scan:",
                "⚠".yellow(),
                failed_scans,
                total_ips
            );
            for result in per_ip_results.values() {
                if let Some(ref err) = result.error {
                    println!("    {} {}", result.ip.to_string().yellow(), err.red());
                }
            }
        }

        // Phase 3: Detect inconsistencies
        println!("\nAnalyzing configuration consistency across backends...");
        let detector = InconsistencyDetector::new(per_ip_results.clone());
        let inconsistencies = detector.detect_all();

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

        // Phase 3: Perform conservative aggregation
        println!("Aggregating results (conservative worst-case approach)...");
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
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

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
