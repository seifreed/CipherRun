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

impl ConnectionArgs {
    /// Effective inter-connection throttle in milliseconds.
    ///
    /// `--sleep` (raw milliseconds) takes precedence; otherwise the human-readable
    /// `--delay` (e.g. "200ms", "1s") is parsed.
    pub fn effective_sleep_ms(&self) -> crate::Result<Option<u64>> {
        if let Some(ms) = self.sleep {
            return Ok(Some(ms));
        }
        self.delay
            .as_deref()
            .map(|d| {
                crate::utils::rate_limiter::parse_delay(d).map(|duration| duration.as_millis() as u64)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: ConnectionArgs,
    }

    #[test]
    fn test_connection_args_defaults_from_clap() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(args.socket_timeout.is_none());
        assert!(args.connect_timeout.is_none());
        assert!(args.sleep.is_none());
        assert!(args.delay.is_none());
        assert_eq!(args.max_retries, 3);
        assert_eq!(args.retry_backoff_ms, 100);
        assert_eq!(args.max_backoff_ms, 5000);
        assert!(!args.no_retry);
    }

    #[test]
    fn test_connection_args_no_retry_flag() {
        let parsed = TestCli::parse_from(["test", "--no-retry"]);
        let args = parsed.args;
        assert!(args.no_retry);
    }

    #[test]
    fn test_effective_sleep_ms_parses_delay_string() {
        let parsed = TestCli::parse_from(["test", "--delay", "1s"]);
        assert_eq!(parsed.args.effective_sleep_ms().unwrap(), Some(1000));

        let parsed = TestCli::parse_from(["test", "--delay", "250ms"]);
        assert_eq!(parsed.args.effective_sleep_ms().unwrap(), Some(250));
    }

    #[test]
    fn test_effective_sleep_ms_prefers_explicit_sleep() {
        let parsed = TestCli::parse_from(["test", "--sleep", "500", "--delay", "1s"]);
        assert_eq!(parsed.args.effective_sleep_ms().unwrap(), Some(500));
    }

    #[test]
    fn test_effective_sleep_ms_none_when_unset() {
        let parsed = TestCli::parse_from(["test"]);
        assert_eq!(parsed.args.effective_sleep_ms().unwrap(), None);
    }

    #[test]
    fn test_effective_sleep_ms_rejects_invalid_delay() {
        let args = ConnectionArgs {
            delay: Some("nope".to_string()),
            ..Default::default()
        };

        assert!(args.effective_sleep_ms().is_err());
    }

    #[test]
    fn test_connection_args_max_retries_zero() {
        let parsed = TestCli::parse_from(["test", "--max-retries", "0"]);
        let args = parsed.args;
        assert_eq!(args.max_retries, 0);
    }
}
