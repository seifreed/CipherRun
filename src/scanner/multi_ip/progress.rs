use crate::scanner::inconsistency::Inconsistency;
use colored::*;

/// Progress information for a completed IP scan.
#[derive(Debug, Clone)]
pub struct IpScanProgress<'a> {
    pub ip: &'a str,
    pub index: usize,
    pub total: usize,
    pub success: bool,
    pub duration_secs: f64,
    pub error: Option<&'a str>,
}

/// Summary of a multi-IP scan operation.
#[derive(Debug, Clone)]
pub struct MultiIpScanSummary<'a> {
    pub total_ips: usize,
    pub successful: usize,
    pub failed: usize,
    pub duration_secs: f64,
    pub failed_results: &'a [(std::net::IpAddr, String)],
}

pub trait MultiIpProgressCallback: Send + Sync {
    fn on_scan_start(&self, total_ips: usize);
    fn on_ip_start(&self, ip: &str, index: usize, total: usize);
    fn on_ip_complete(&self, progress: &IpScanProgress<'_>);
    fn on_scan_summary(&self, summary: &MultiIpScanSummary<'_>);
    fn on_consistency_analysis_start(&self);
    fn on_consistency_analysis_complete(&self, inconsistencies: &[Inconsistency]);
    fn on_aggregation_start(&self);
}

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
                if inconsistencies.len() == 1 { "y" } else { "ies" }
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
