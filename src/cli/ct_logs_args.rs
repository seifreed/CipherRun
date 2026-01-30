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
