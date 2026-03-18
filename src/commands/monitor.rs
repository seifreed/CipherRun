// MonitorCommand - Certificate monitoring daemon
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{Command, CommandExit};
use crate::application::HostPortInput;
use crate::{Args, Result, TlsError};
use async_trait::async_trait;
use tracing::info;

/// MonitorCommand handles certificate monitoring operations
///
/// This command is responsible for:
/// - Testing alert channels (--test-alert)
/// - Starting the monitoring daemon (--monitor)
/// - Loading monitoring configuration
/// - Loading domains to monitor from file or CLI
pub struct MonitorCommand {
    args: Args,
}

impl MonitorCommand {
    /// Create a new MonitorCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    fn load_monitor_config(&self) -> Result<crate::monitor::MonitorConfig> {
        use crate::monitor::MonitorConfig;

        if let Some(config_path) = &self.args.monitoring.config {
            let config_str = std::fs::read_to_string(config_path)?;
            toml::from_str(&config_str)
                .map_err(|e| TlsError::Other(format!("Failed to parse TOML config: {}", e)))
        } else {
            Ok(MonitorConfig::default())
        }
    }

    fn print_alert_test_results(&self, results: Vec<(String, Result<()>)>) {
        println!("\nAlert Channel Tests:");
        println!("{}", "=".repeat(80));

        if results.is_empty() {
            println!("No alert channels configured");
        } else {
            for (channel_name, result) in results {
                let status = if result.is_ok() { "✓" } else { "✗" };
                let message = result
                    .as_ref()
                    .map(|_| "Success".to_string())
                    .unwrap_or_else(|e| format!("Failed: {}", e));
                println!("  {} {} - {}", status, channel_name, message);
            }
        }
        println!();
    }

    async fn handle_test_alerts(
        &self,
        monitor_config: crate::monitor::MonitorConfig,
    ) -> Result<CommandExit> {
        use crate::monitor::MonitorDaemon;

        info!("Testing alert channels...");
        let daemon = MonitorDaemon::new(monitor_config).await?;
        let results = daemon.test_alerts().await;
        self.print_alert_test_results(results);

        Ok(CommandExit::success())
    }

    async fn load_domains_from_file(&self, daemon: &crate::monitor::MonitorDaemon) -> Result<()> {
        if let Some(domains_file) = &self.args.monitoring.domains_file {
            let path_str = domains_file
                .to_str()
                .ok_or_else(|| TlsError::InvalidInput {
                    message: "Invalid domains file path".to_string(),
                })?;
            daemon.load_domains(path_str).await?;
        }

        Ok(())
    }

    async fn add_single_domain(&self, daemon: &crate::monitor::MonitorDaemon) -> Result<()> {
        use crate::monitor::MonitoredDomain;

        if let Some(domain_str) = &self.args.monitoring.domain {
            let parsed = HostPortInput::parse_with_default_port(domain_str, 443);
            let domain = MonitoredDomain::new(parsed.hostname, parsed.port);
            daemon.add_domain(domain).await?;
        }

        Ok(())
    }

    async fn handle_monitor_start(
        &self,
        monitor_config: crate::monitor::MonitorConfig,
    ) -> Result<CommandExit> {
        use crate::monitor::MonitorDaemon;

        info!("Starting certificate monitoring daemon");

        let daemon = MonitorDaemon::new(monitor_config).await?;
        self.load_domains_from_file(&daemon).await?;
        self.add_single_domain(&daemon).await?;
        daemon.start().await?;

        Ok(CommandExit::success())
    }
}

#[async_trait]
impl Command for MonitorCommand {
    async fn execute(&self) -> Result<CommandExit> {
        let monitor_config = self.load_monitor_config()?;

        if self.args.monitoring.test_alert {
            return self.handle_test_alerts(monitor_config).await;
        }

        if self.args.monitoring.enable {
            return self.handle_monitor_start(monitor_config).await;
        }

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "MonitorCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_command_name() {
        let cmd = MonitorCommand::new(Args::default());
        assert_eq!(cmd.name(), "MonitorCommand");
    }

    #[tokio::test]
    async fn test_monitor_command_noop_without_flags() {
        let args = Args::default();
        let cmd = MonitorCommand::new(args);
        cmd.execute().await.expect("no-op should succeed");
    }
}
