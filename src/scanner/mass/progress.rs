use crate::Result;
use crate::scanner::ScanResults;
use colored::*;
use std::time::Duration;

/// Progress information for a completed target scan.
#[derive(Debug)]
pub struct TargetScanProgress<'a> {
    pub target: &'a str,
    pub index: usize,
    pub total: usize,
    pub result: &'a Result<ScanResults>,
    pub duration: Duration,
}

pub trait MassScanProgressCallback: Send + Sync {
    fn on_serial_scan_start(&self, total_targets: usize);
    fn on_parallel_scan_start(&self, total_targets: usize, max_concurrent: usize);
    fn on_target_start(&self, target: &str, index: usize, total: usize);
    fn on_target_complete(&self, progress: &TargetScanProgress<'_>);
    fn on_parallel_progress(&self, completed: usize, total: usize, current_target: &str);
    fn on_all_scans_complete(&self);
}

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

    fn on_parallel_progress(&self, _completed: usize, _total: usize, _current_target: &str) {}

    fn on_all_scans_complete(&self) {}
}

pub struct SilentMassProgress;

impl MassScanProgressCallback for SilentMassProgress {
    fn on_serial_scan_start(&self, _total_targets: usize) {}
    fn on_parallel_scan_start(&self, _total_targets: usize, _max_concurrent: usize) {}
    fn on_target_start(&self, _target: &str, _index: usize, _total: usize) {}
    fn on_target_complete(&self, _progress: &TargetScanProgress<'_>) {}
    fn on_parallel_progress(&self, _completed: usize, _total: usize, _current_target: &str) {}
    fn on_all_scans_complete(&self) {}
}
