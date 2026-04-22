use super::command::{Command, CommandExit};
use crate::pqc::scanners::{CodeScanner, SshScanner, VpnScanner};
use crate::Result;
use async_trait::async_trait;
use colored::*;
use std::path::PathBuf;

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
        Self { ssh_path, vpn_path, code_path }
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
            match SshScanner::scan(path) {
                Ok(result) => {
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
                Err(e) => {
                    println!("  {} Failed to scan SSH config: {}", "X".red(), e);
                }
            }
        }

        if let Some(path) = &self.vpn_path {
            println!("\n{}", "=== VPN Configuration Audit ===".bold());
            match VpnScanner::scan(path) {
                Ok(result) => {
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
                Err(e) => {
                    println!("  {} Failed to scan VPN config: {}", "X".red(), e);
                }
            }
        }

        if let Some(path) = &self.code_path {
            println!("\n{}", "=== Source Code Audit ===".bold());
            match CodeScanner::scan(path) {
                Ok(result) => {
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
                Err(e) => {
                    println!("  {} Failed to scan source code: {}", "X".red(), e);
                }
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

    #[tokio::test]
    async fn test_pqc_scan_no_paths_returns_success() {
        let cmd = PqcScanCommand::new(None, None, None);
        let exit = cmd.execute().await.expect("should succeed");
        assert!(exit.is_success());
    }

    #[test]
    fn test_pqc_scan_command_name() {
        let cmd = PqcScanCommand::new(None, None, None);
        assert_eq!(cmd.name(), "PqcScanCommand");
    }
}
