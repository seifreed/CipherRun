// MonitorCommand - Certificate monitoring daemon
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{Command, CommandExit};
use crate::application::HostPortInput;
use crate::{Args, Result};
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
            MonitorConfig::from_file(config_path)
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
                let message = alert_test_message(&result);
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

        info!(
            event_name = "monitor.alert_test.started",
            "Testing alert channels"
        );
        let daemon = MonitorDaemon::new(monitor_config).await?;
        let results = daemon.test_alerts().await;
        self.print_alert_test_results(results);

        Ok(CommandExit::success())
    }

    async fn load_domains_from_file(&self, daemon: &crate::monitor::MonitorDaemon) -> Result<()> {
        if let Some(domains_file) = &self.args.monitoring.domains_file {
            daemon.load_domains(domains_file).await?;
        }

        Ok(())
    }

    async fn add_single_domain(
        &self,
        daemon: &crate::monitor::MonitorDaemon,
        default_interval_seconds: u64,
    ) -> Result<()> {
        use crate::monitor::MonitoredDomain;

        if let Some(domain_str) = &self.args.monitoring.domain {
            let parsed = HostPortInput::parse_with_default_port(domain_str, 443)?;
            let domain = MonitoredDomain::new(parsed.hostname, parsed.port)
                .with_interval(default_interval_seconds);
            daemon.add_domain(domain).await?;
        }

        Ok(())
    }

    async fn handle_monitor_start(
        &self,
        monitor_config: crate::monitor::MonitorConfig,
    ) -> Result<CommandExit> {
        use crate::monitor::MonitorDaemon;

        info!(
            event_name = "monitor.command.started",
            "Starting certificate monitoring daemon"
        );

        let default_interval_seconds = monitor_config.monitor.default_interval_seconds;
        let daemon = MonitorDaemon::new(monitor_config).await?;
        self.load_domains_from_file(&daemon).await?;
        self.add_single_domain(&daemon, default_interval_seconds)
            .await?;
        daemon.start().await?;

        Ok(CommandExit::success())
    }
}

fn alert_test_message(result: &Result<()>) -> String {
    match result {
        Ok(()) => "Success".to_string(),
        Err(error) => format!("Failed (error_code={})", error.observability_code()),
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

    #[test]
    fn alert_test_message_does_not_expose_remote_error_body() {
        let error = crate::TlsError::HttpError {
            status: 503,
            details: "token=do-not-print\ninjected=true".to_string(),
        };

        let message = alert_test_message(&Err(error));

        assert_eq!(message, "Failed (error_code=http_error)");
        assert!(!message.contains("do-not-print"));
        assert!(!message.contains("injected=true"));
    }

    #[tokio::test]
    async fn test_monitor_command_noop_without_flags() {
        let args = Args::default();
        let cmd = MonitorCommand::new(args);
        cmd.execute().await.expect("no-op should succeed");
    }

    #[tokio::test]
    async fn test_alert_mode_succeeds_without_configured_channels() {
        let mut args = Args::default();
        args.monitoring.test_alert = true;

        MonitorCommand::new(args)
            .execute()
            .await
            .expect("testing an empty alert configuration should succeed");
    }

    #[tokio::test]
    async fn domain_sources_load_from_file_and_command_line() {
        let daemon = crate::monitor::MonitorDaemon::new(crate::monitor::MonitorConfig::default())
            .await
            .unwrap();
        let empty = MonitorCommand::new(Args::default());
        empty.load_domains_from_file(&daemon).await.unwrap();
        empty.add_single_domain(&daemon, 600).await.unwrap();

        let directory = tempfile::tempdir().unwrap();
        let domains_file = directory.path().join("domains.txt");
        std::fs::write(&domains_file, "mail.example.net 5m\n").unwrap();
        let mut args = Args::default();
        args.monitoring.domains_file = Some(domains_file);
        args.monitoring.domain = Some("example.com:8443".to_string());
        let command = MonitorCommand::new(args);
        command.load_domains_from_file(&daemon).await.unwrap();
        command.add_single_domain(&daemon, 600).await.unwrap();

        assert_eq!(daemon.stats().await.total_domains, 2);
    }

    #[test]
    fn test_load_monitor_config_rejects_invalid_file() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        std::fs::write(
            &path,
            r#"
[monitor]
default_interval_seconds = 0
max_concurrent_scans = 1
"#,
        )
        .expect("test assertion should succeed");

        let mut args = Args::default();
        args.monitoring.config = Some(path);
        let cmd = MonitorCommand::new(args);
        let err = cmd
            .load_monitor_config()
            .expect_err("invalid monitor config should fail");

        assert!(err.to_string().contains("default_interval_seconds"));
    }

    #[test]
    fn test_load_monitor_config_reads_valid_file() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        std::fs::write(
            &path,
            "[monitor]\ndefault_interval_seconds = 600\nmax_concurrent_scans = 2\n",
        )
        .expect("test assertion should succeed");

        let mut args = Args::default();
        args.monitoring.config = Some(path);
        let config = MonitorCommand::new(args)
            .load_monitor_config()
            .expect("valid monitor config should load");

        assert_eq!(config.monitor.default_interval_seconds, 600);
        assert_eq!(config.monitor.max_concurrent_scans, 2);
    }
}
