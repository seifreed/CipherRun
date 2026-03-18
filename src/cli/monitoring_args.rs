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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: MonitoringArgs,
    }

    #[test]
    fn test_monitoring_args_defaults_from_clap() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(!args.enable);
        assert!(args.config.is_none());
        assert!(args.domains_file.is_none());
        assert!(args.domain.is_none());
        assert!(!args.test_alert);
    }

    #[test]
    fn test_monitoring_args_enable_and_domain() {
        let parsed =
            TestCli::parse_from(["test", "--monitor", "--monitor-domain", "example.com:443"]);
        let args = parsed.args;

        assert!(args.enable);
        assert_eq!(args.domain.as_deref(), Some("example.com:443"));
    }
}
