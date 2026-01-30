// Certificate monitoring daemon configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;
use std::path::PathBuf;

/// Certificate monitoring daemon options
///
/// This struct contains all arguments related to certificate expiration monitoring,
/// including daemon configuration, domain lists, and alert testing.
#[derive(Args, Debug, Clone, Default)]
pub struct MonitoringArgs {
    /// Start the monitoring daemon
    #[arg(long = "monitor", id = "monitor_enable")]
    pub enable: bool,

    /// Monitoring configuration file (TOML format)
    #[arg(long = "monitor-config", value_name = "FILE", id = "monitor_config")]
    pub config: Option<PathBuf>,

    /// File with domains to monitor (one per line, host:port format)
    #[arg(long = "monitor-domains", value_name = "FILE")]
    pub domains_file: Option<PathBuf>,

    /// Single domain to monitor (host:port format)
    #[arg(long = "monitor-domain", value_name = "HOST:PORT")]
    pub domain: Option<String>,

    /// Test alert channels (send test alert to all configured channels)
    #[arg(long = "test-alert")]
    pub test_alert: bool,
}
