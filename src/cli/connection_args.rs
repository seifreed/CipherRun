// Connection and timeout configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;

/// Connection and timeout configuration options
///
/// This struct contains all arguments related to connection timeouts,
/// retry logic, and connection timing behavior.
#[derive(Args, Debug, Clone)]
pub struct ConnectionArgs {
    /// Socket timeout in seconds
    #[arg(long = "socket-timeout", value_name = "SECONDS")]
    pub socket_timeout: Option<u64>,

    /// Connection timeout in seconds (separate from socket timeout)
    #[arg(long = "connect-timeout", value_name = "SECONDS")]
    pub connect_timeout: Option<u64>,

    /// Sleep between connection requests in milliseconds
    #[arg(long = "sleep", value_name = "MSEC")]
    pub sleep: Option<u64>,

    /// Delay between connections (e.g "200ms", "1s")
    #[arg(long = "delay")]
    pub delay: Option<String>,

    /// Maximum number of retries for transient network failures (0 = no retries)
    /// Helps distinguish between permanent failures (connection refused) and
    /// transient failures (timeouts, connection resets)
    #[arg(long = "max-retries", value_name = "COUNT", default_value = "3")]
    pub max_retries: usize,

    /// Initial backoff duration in milliseconds for retry logic
    /// Backoff doubles with each retry (exponential backoff) up to max-backoff
    #[arg(long = "retry-backoff", value_name = "MSEC", default_value = "100")]
    pub retry_backoff_ms: u64,

    /// Maximum backoff duration in milliseconds for retry logic
    /// Prevents excessive delays during multiple retries
    #[arg(long = "max-backoff", value_name = "MSEC", default_value = "5000")]
    pub max_backoff_ms: u64,

    /// Disable retry logic (fail immediately on first error)
    /// Equivalent to --max-retries 0
    #[arg(long = "no-retry")]
    pub no_retry: bool,
}

impl Default for ConnectionArgs {
    fn default() -> Self {
        Self {
            socket_timeout: None,
            connect_timeout: None,
            sleep: None,
            delay: None,
            max_retries: 3,
            retry_backoff_ms: 100,
            max_backoff_ms: 5000,
            no_retry: false,
        }
    }
}
