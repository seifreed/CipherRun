use super::command::{Command, CommandExit};
use crate::Result;
use crate::pqc::scanners::{CodeScanner, SshScanner, VpnScanner};
use async_trait::async_trait;
use colored::Colorize;
use std::path::PathBuf;
use std::time::Instant;
use tracing::info;

pub struct PqcScanCommand {
    ssh_path: Option<PathBuf>,
    vpn_path: Option<PathBuf>,
    code_path: Option<PathBuf>,
}

impl PqcScanCommand {
    pub fn new(
        ssh_path: Option<PathBuf>,
        vpn_path: Option<PathBuf>,
        code_path: Option<PathBuf>,
    ) -> Self {
        Self {
            ssh_path,
            vpn_path,
            code_path,
        }
    }
}

#[async_trait]
impl Command for PqcScanCommand {
    fn name(&self) -> &'static str {
        "PqcScanCommand"
    }

    async fn execute(&self) -> Result<CommandExit> {
        let mut any_findings = false;

        if let Some(path) = &self.ssh_path {
            println!("\n{}", "=== SSH Configuration Audit ===".bold());
            let started = Instant::now();
            match SshScanner::scan(path) {
                Ok(result) => {
                    info!(
                        event_name = "pqc.scan.completed",
                        operation = "ssh_config",
                        duration_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        findings_count = result.quantum_vulnerable.len(),
                        outcome = "success",
                        "PQC configuration scan completed"
                    );
                    println!("  File:  {}", result.path);
                    println!("  Score: {}/100", result.score);
                    if !result.quantum_vulnerable.is_empty() {
                        any_findings = true;
                        println!("\n  {} Quantum-vulnerable algorithms:", "!".red().bold());
                        for alg in &result.quantum_vulnerable {
                            println!("    - {}", alg.red());
                        }
                    }
                    if !result.pqc_safe.is_empty() {
                        println!("\n  {} PQC-safe algorithms:", "Y".green().bold());
                        for alg in &result.pqc_safe {
                            println!("    - {}", alg.green());
                        }
                    }
                    if !result.recommendations.is_empty() {
                        println!("\n  Recommendations:");
                        for rec in &result.recommendations {
                            println!("    - {}", rec.yellow());
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if let Some(path) = &self.vpn_path {
            println!("\n{}", "=== VPN Configuration Audit ===".bold());
            let started = Instant::now();
            match VpnScanner::scan(path) {
                Ok(result) => {
                    info!(
                        event_name = "pqc.scan.completed",
                        operation = "vpn_config",
                        duration_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        findings_count = result.quantum_vulnerable.len(),
                        outcome = "success",
                        "PQC configuration scan completed"
                    );
                    println!("  File:     {}", result.path);
                    println!("  VPN type: {}", result.vpn_type);
                    println!("  Score:    {}/100", result.score);
                    if !result.quantum_vulnerable.is_empty() {
                        any_findings = true;
                        println!("\n  {} Quantum-vulnerable:", "!".red().bold());
                        for item in &result.quantum_vulnerable {
                            println!("    - {}", item.red());
                        }
                    }
                    if !result.recommendations.is_empty() {
                        println!("\n  Recommendations:");
                        for rec in &result.recommendations {
                            println!("    - {}", rec.yellow());
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if let Some(path) = &self.code_path {
            println!("\n{}", "=== Source Code Audit ===".bold());
            let started = Instant::now();
            match CodeScanner::scan(path) {
                Ok(result) => {
                    info!(
                        event_name = "pqc.scan.completed",
                        operation = "source_code",
                        duration_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        files_scanned = result.files_scanned,
                        findings_count = result.findings.len(),
                        outcome = "success",
                        "PQC source scan completed"
                    );
                    println!("  Root:          {}", result.root);
                    println!("  Files scanned: {}", result.files_scanned);
                    println!("  Findings:      {}", result.findings.len());
                    if !result.findings.is_empty() {
                        any_findings = true;
                        println!();
                        for finding in &result.findings {
                            let severity_colored = if finding.severity == "High" {
                                finding.severity.red().bold()
                            } else {
                                finding.severity.yellow().bold()
                            };
                            println!(
                                "  [{}] {}:{} — {} ({})",
                                severity_colored,
                                finding.file,
                                finding.line,
                                finding.algorithm.cyan(),
                                finding.pattern
                            );
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if self.ssh_path.is_none() && self.vpn_path.is_none() && self.code_path.is_none() {
            println!(
                "{}",
                "No paths specified. Use --ssh, --vpn, or --code to select what to scan.".yellow()
            );
            return Ok(CommandExit::success());
        }

        if any_findings {
            Ok(CommandExit::failure(1))
        } else {
            Ok(CommandExit::success())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogWriter(self.0.clone())
        }
    }

    #[test]
    fn captured_log_writer_flushes_successfully() {
        let mut writer = CapturedLogWriter(Arc::new(Mutex::new(Vec::new())));

        writer
            .flush()
            .expect("in-memory writer flush should succeed");
    }

    #[test]
    fn configured_scans_log_duration_and_counts_without_recording_paths() {
        let directory = tempfile::tempdir().unwrap();
        let ssh_path = directory.path().join("private-ssh.conf");
        let vpn_path = directory.path().join("private-vpn.conf");
        let source_path = directory.path().join("private-source.rs");
        std::fs::write(&ssh_path, "").unwrap();
        std::fs::write(&vpn_path, "").unwrap();
        std::fs::write(&source_path, "fn safe_example() {}\n").unwrap();
        let command = PqcScanCommand::new(
            Some(ssh_path.clone()),
            Some(vpn_path.clone()),
            Some(source_path.clone()),
        );
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(CapturedLog(output.clone()))
            .finish();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            assert!(
                runtime
                    .block_on(command.execute())
                    .expect("source scan should succeed")
                    .is_success()
            );
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert_eq!(output.matches("pqc.scan.completed").count(), 3, "{output}");
        assert!(output.contains("ssh_config"), "{output}");
        assert!(output.contains("vpn_config"), "{output}");
        assert!(output.contains("source_code"), "{output}");
        assert!(output.contains("duration_ms"), "{output}");
        assert!(output.contains("findings_count"), "{output}");
        assert!(!output.contains(ssh_path.to_str().unwrap()), "{output}");
        assert!(!output.contains(vpn_path.to_str().unwrap()), "{output}");
        assert!(!output.contains(source_path.to_str().unwrap()), "{output}");
    }

    #[tokio::test]
    async fn test_pqc_scan_no_paths_returns_success() {
        let cmd = PqcScanCommand::new(None, None, None);
        let exit = cmd.execute().await.expect("should succeed");
        assert!(exit.is_success());
    }

    #[tokio::test]
    async fn test_pqc_scan_unreadable_path_returns_error() {
        let cmd = PqcScanCommand::new(
            Some(PathBuf::from("/nonexistent/cipherrun-pqc-test/ssh_config")),
            None,
            None,
        );
        cmd.execute()
            .await
            .expect_err("unreadable path should propagate scanner error");
    }

    #[test]
    fn test_pqc_scan_command_name() {
        let cmd = PqcScanCommand::new(None, None, None);
        assert_eq!(cmd.name(), "PqcScanCommand");
    }
}
