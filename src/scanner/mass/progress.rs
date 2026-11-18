use crate::Result;
use crate::scanner::ScanResults;
use colored::Colorize;
use std::time::Duration;
use tracing::debug;

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
            Err(error) => {
                debug!(
                    event_name = "mass_scan.target.failed",
                    scan_index = progress.index,
                    total_targets = progress.total,
                    duration_ms = u64::try_from(progress.duration.as_millis()).unwrap_or(u64::MAX),
                    error_type = "scan",
                    error_code = error.observability_code(),
                    outcome = "failed",
                    "Mass scan target failed"
                );
                println!("  {} Scan failed", "ERR".red());
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

#[cfg(test)]
mod tests {
    use super::{
        MassScanProgressCallback, SilentMassProgress, TargetScanProgress, TerminalMassProgress,
    };
    use crate::application::ScanResults;
    use crate::rating::{Grade, RatingResult};
    use crate::scanner::RatingResults;
    use crate::{Result, TlsError};
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedWriter(self.0.clone())
        }
    }

    #[test]
    fn terminal_progress_handles_scan_lifecycle_and_outcomes() {
        let progress = TerminalMassProgress::new();
        let _default_progress: TerminalMassProgress = Default::default();
        progress.on_serial_scan_start(2);
        progress.on_parallel_scan_start(2, 2);
        progress.on_target_start("example.com", 1, 2);

        let successful = Ok(ScanResults::default());
        progress.on_target_complete(&TargetScanProgress {
            target: "example.com",
            index: 1,
            total: 2,
            result: &successful,
            duration: Duration::from_millis(1200),
        });

        let rated = Ok(ScanResults {
            rating: Some(RatingResults {
                ssl_rating: Some(RatingResult {
                    grade: Grade::A,
                    score: 95,
                    certificate_score: 95,
                    protocol_score: 95,
                    key_exchange_score: 95,
                    cipher_strength_score: 95,
                    warnings: Vec::new(),
                }),
            }),
            ..Default::default()
        });
        progress.on_target_complete(&TargetScanProgress {
            target: "rated.example.com",
            index: 2,
            total: 2,
            result: &rated,
            duration: Duration::from_secs(2),
        });

        let failed: Result<ScanResults> = Err(TlsError::Other("connection failed".to_string()));
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            progress.on_target_complete(&TargetScanProgress {
                target: "failed.example.com",
                index: 2,
                total: 2,
                result: &failed,
                duration: Duration::from_millis(10),
            });
        });
        output.make_writer().flush().unwrap();
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["event_name"], "mass_scan.target.failed");
        assert_eq!(event["fields"]["scan_index"], 2);
        assert_eq!(event["fields"]["total_targets"], 2);
        assert_eq!(event["fields"]["duration_ms"], 10);
        assert_eq!(event["fields"]["error_type"], "scan");
        assert!(event["fields"]["error_code"].is_string());
        assert_eq!(event["fields"]["outcome"], "failed");
        assert_eq!(event["fields"]["message"], "Mass scan target failed");
        progress.on_parallel_progress(2, 2, "example.com");
        progress.on_all_scans_complete();
    }

    #[test]
    fn silent_progress_ignores_scan_lifecycle_events() {
        let progress = SilentMassProgress;
        progress.on_serial_scan_start(1);
        progress.on_parallel_scan_start(1, 1);
        progress.on_target_start("example.com", 1, 1);

        let successful = Ok(ScanResults::default());
        progress.on_target_complete(&TargetScanProgress {
            target: "example.com",
            index: 1,
            total: 1,
            result: &successful,
            duration: Duration::ZERO,
        });
        progress.on_parallel_progress(1, 1, "example.com");
        progress.on_all_scans_complete();
    }
}
