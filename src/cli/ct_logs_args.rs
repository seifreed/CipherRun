// Certificate Transparency logs streaming configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;

/// Certificate Transparency logs streaming options
///
/// This struct contains all arguments related to CT log streaming,
/// including log source configuration, polling intervals, and output formats.
#[derive(Args, Debug, Clone, Default)]
pub struct CtLogsArgs {
    /// Enable Certificate Transparency logs streaming mode
    #[arg(long = "ct-logs", alias = "ctl", id = "ct_logs_enable")]
    pub enable: bool,

    /// Start from beginning of CT logs (index 0)
    #[arg(long = "ct-beginning", alias = "cb", requires = "ct_logs_enable")]
    pub beginning: bool,

    /// Start from custom index per log (format: sourceID=index)
    #[arg(
        long = "ct-index",
        alias = "cti",
        requires = "ct_logs_enable",
        value_name = "SOURCE=INDEX"
    )]
    pub index: Vec<String>,

    /// CT logs poll interval in seconds (default: 60)
    #[arg(long = "ct-poll-interval", default_value = "60")]
    pub poll_interval: u64,

    /// CT logs batch size (default: 1000, max: 1000)
    #[arg(long = "ct-batch-size", default_value = "1000")]
    pub batch_size: u64,

    /// Output CT log entries as JSON (one per line)
    #[arg(long = "ct-json", requires = "ct_logs_enable", id = "ct_json")]
    pub json: bool,

    /// Silent mode for CT logs (no stats output, only certificates)
    #[arg(long = "ct-silent", requires = "ct_logs_enable")]
    pub silent: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: CtLogsArgs,
    }

    #[test]
    fn test_ct_logs_args_defaults_from_clap() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(!args.enable);
        assert!(!args.beginning);
        assert!(args.index.is_empty());
        assert_eq!(args.poll_interval, 60);
        assert_eq!(args.batch_size, 1000);
        assert!(!args.json);
        assert!(!args.silent);
    }

    #[test]
    fn test_ct_logs_args_with_enable_and_flags() {
        let parsed = TestCli::parse_from(["test", "--ct-logs", "--ct-beginning", "--ct-json"]);
        let args = parsed.args;

        assert!(args.enable);
        assert!(args.beginning);
        assert!(args.json);
        assert!(!args.silent);
    }

    #[test]
    fn test_ct_logs_args_custom_intervals() {
        let parsed = TestCli::parse_from([
            "test",
            "--ct-logs",
            "--ct-poll-interval",
            "15",
            "--ct-batch-size",
            "500",
        ]);
        let args = parsed.args;

        assert!(args.enable);
        assert_eq!(args.poll_interval, 15);
        assert_eq!(args.batch_size, 500);
    }
}
