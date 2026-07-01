// AnycastScanCommand - Scan every resolved IP of a target for Anycast detection
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{Command, CommandExit};
use crate::utils::anycast::AnycastScanner;
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
        args.port.or_else(|| {
            args.starttls
                .starttls_protocol()
                .map(|protocol| protocol.default_port())
        })
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
        results.display_summary();

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "AnycastScanCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
