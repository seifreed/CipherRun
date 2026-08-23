// AnycastScanCommand - Scan every resolved IP of a target for Anycast detection
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::scan_exporter::{ExportKind, ScanExporter};
use super::{Command, CommandExit};
use crate::utils::anycast::{AnycastScanResults, AnycastScanner};
use crate::utils::network::Target;
use crate::{Args, Result, TlsError};
use async_trait::async_trait;

/// AnycastScanCommand scans all A/AAAA addresses of a single target and compares
/// their certificates and behavior to detect Anycast deployments.
///
/// Triggered by `--scan-all-ips`. Unlike the default multi-IP path (which scans
/// resolved IPs but reports an aggregated view), this runs the dedicated
/// `AnycastScanner` and prints its per-IP comparison and Anycast verdict.
pub struct AnycastScanCommand {
    args: Args,
}

impl AnycastScanCommand {
    /// Create a new AnycastScanCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    fn port_override(args: &Args) -> Option<u16> {
        args.port.or_else(|| args.starttls.starttls_port())
    }

    fn exit_for_results(results: &AnycastScanResults) -> CommandExit {
        if results.successful_scans < results.total_ips {
            CommandExit::failure(1)
        } else {
            CommandExit::success()
        }
    }

    fn export_results(&self, results: &AnycastScanResults) -> Result<()> {
        let exporter = ScanExporter::new(&self.args);
        let Some(json_path) = exporter.collection_json_output_path()? else {
            return Ok(());
        };
        let json = if self.args.output.json_pretty {
            serde_json::to_string_pretty(results)?
        } else {
            serde_json::to_string(results)?
        };
        exporter.write_text_file(&json_path, &json, "JSON", ExportKind::Json)
    }
}

#[async_trait]
impl Command for AnycastScanCommand {
    async fn execute(&self) -> Result<CommandExit> {
        let target_input = self.args.target.as_deref().ok_or(TlsError::InvalidInput {
            message: "--scan-all-ips requires a target".to_string(),
        })?;

        let target =
            Target::parse_with_port_override(target_input, Self::port_override(&self.args)).await?;

        let scanner = AnycastScanner::new(target.hostname.clone(), target.port, self.args.clone());
        let results = scanner.scan_all_ips().await?;
        if !self.args.output.quiet {
            results.display_summary();
        }
        self.export_results(&results)?;

        let exit = Self::exit_for_results(&results);
        if exit.is_success()
            && self.args.output.fail_on.is_some_and(|threshold| {
                results
                    .ip_results
                    .iter()
                    .any(|result| threshold.is_met_by(&result.results))
            })
        {
            return Ok(CommandExit::findings_failure());
        }

        Ok(exit)
    }

    fn name(&self) -> &'static str {
        "AnycastScanCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::anycast::{AnycastDetection, IpScanResult};
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_anycast_scan_command_name() {
        let args = Args::default();
        let cmd = AnycastScanCommand::new(args);
        assert_eq!(cmd.name(), "AnycastScanCommand");
    }

    #[test]
    fn test_port_override_uses_starttls_default_port() {
        let args = Args {
            starttls: crate::cli::StarttlsArgs {
                smtp: true,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(AnycastScanCommand::port_override(&args), Some(25));
    }

    #[test]
    fn test_port_override_uses_xmpp_server_port() {
        let args = Args {
            starttls: crate::cli::StarttlsArgs {
                xmpp_server: true,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(AnycastScanCommand::port_override(&args), Some(5269));
    }

    #[test]
    fn test_explicit_port_overrides_starttls_default_port() {
        let args = Args {
            port: Some(8443),
            starttls: crate::cli::StarttlsArgs {
                smtp: true,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(AnycastScanCommand::port_override(&args), Some(8443));
    }

    fn anycast_results(total_ips: usize, successful_scans: usize) -> AnycastScanResults {
        AnycastScanResults {
            hostname: "example.test".to_string(),
            port: 443,
            total_ips,
            successful_scans,
            ip_results: vec![IpScanResult {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                results: Default::default(),
                error: (successful_scans < total_ips).then(|| "timeout".to_string()),
            }],
            anycast_detection: AnycastDetection {
                is_anycast: false,
                confidence: 0.0,
                reasons: Vec::new(),
                certificate_fingerprints: HashSet::new(),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            },
        }
    }

    #[test]
    fn test_anycast_scan_partial_failure_returns_failure() {
        let exit = AnycastScanCommand::exit_for_results(&anycast_results(2, 1));
        assert!(!exit.is_success());
    }

    #[test]
    fn test_anycast_scan_all_success_returns_success() {
        let exit = AnycastScanCommand::exit_for_results(&anycast_results(2, 2));
        assert!(exit.is_success());
    }

    #[test]
    fn test_anycast_json_export_writes_results() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("anycast.json");
        let args = Args {
            output: crate::cli::OutputArgs {
                json: Some(path.clone()),
                overwrite: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let command = AnycastScanCommand::new(args);

        command
            .export_results(&anycast_results(1, 1))
            .expect("Anycast JSON export should succeed");
        let exported: AnycastScanResults =
            serde_json::from_str(&std::fs::read_to_string(path).expect("JSON should be written"))
                .expect("exported JSON should deserialize");
        assert_eq!(exported.total_ips, 1);
        assert_eq!(exported.successful_scans, 1);
    }
}
