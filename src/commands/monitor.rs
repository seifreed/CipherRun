// MonitorCommand - Certificate monitoring daemon
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
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
}

#[async_trait]
impl Command for MonitorCommand {
    async fn execute(&self) -> Result<()> {
        use crate::monitor::{MonitorConfig, MonitorDaemon, MonitoredDomain};

        // Load or create monitoring configuration
        let monitor_config = if let Some(config_path) = &self.args.monitoring.config {
            let config_str = std::fs::read_to_string(config_path)?;
            toml::from_str(&config_str)
                .map_err(|e| TlsError::Other(format!("Failed to parse TOML config: {}", e)))?
        } else {
            // Create default configuration
            MonitorConfig::default()
        };

        // Handle test alert
        if self.args.monitoring.test_alert {
            info!("Testing alert channels...");
            let daemon = MonitorDaemon::new(monitor_config).await?;
            let results = daemon.test_alerts().await;

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

            return Ok(());
        }

        // Handle monitor daemon start
        if self.args.monitoring.enable {
            info!("Starting certificate monitoring daemon");

            let daemon = MonitorDaemon::new(monitor_config).await?;

            // Load domains from file
            if let Some(domains_file) = &self.args.monitoring.domains_file {
                let path_str = domains_file
                    .to_str()
                    .ok_or_else(|| TlsError::InvalidInput {
                        message: "Invalid domains file path".to_string(),
                    })?;
                daemon.load_domains(path_str).await?;
            }

            // Add single domain if specified
            if let Some(domain_str) = &self.args.monitoring.domain {
                let parts: Vec<&str> = domain_str.split(':').collect();
                let hostname = parts.first().copied().unwrap_or("localhost");
                let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

                let domain = MonitoredDomain::new(hostname.to_string(), port);

                daemon.add_domain(domain).await?;
            }

            // Start the monitoring daemon
            daemon.start().await?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "MonitorCommand"
    }
}
