// HTTP and application configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;

/// HTTP and application layer configuration options
///
/// This struct contains all arguments related to HTTP configuration,
/// including authentication, headers, user agent, and operational modes.
#[derive(Args, Debug, Clone, Default)]
pub struct HttpArgs {
    // ============ HTTP Authentication and Headers ============
    /// HTTP Basic Authentication (user:password)
    #[arg(long = "basicauth", value_name = "USER:PASS")]
    pub basicauth: Option<String>,

    /// Custom User-Agent string
    #[arg(long = "user-agent", value_name = "STRING")]
    pub user_agent: Option<String>,

    /// Custom HTTP request headers (can be specified multiple times)
    #[arg(long = "reqheader", value_name = "HEADER")]
    pub custom_headers: Vec<String>,

    /// Assume HTTP protocol when detection fails
    #[arg(long = "assume-http")]
    pub assume_http: bool,

    // ============ Operational Modes ============
    /// IDS-friendly mode (slower, avoid triggering IDS/IPS)
    #[arg(long = "ids-friendly")]
    pub ids_friendly: bool,

    /// Sneaky mode - leave less traces in target logs
    #[arg(long = "sneaky")]
    pub sneaky: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: HttpArgs,
    }

    #[test]
    fn test_http_args_defaults_from_clap() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(args.basicauth.is_none());
        assert!(args.user_agent.is_none());
        assert!(args.custom_headers.is_empty());
        assert!(!args.assume_http);
        assert!(!args.ids_friendly);
        assert!(!args.sneaky);
    }

    #[test]
    fn test_http_args_custom_headers_multiple() {
        let parsed = TestCli::parse_from([
            "test",
            "--reqheader",
            "X-Test: 1",
            "--reqheader",
            "X-Other: 2",
        ]);
        let args = parsed.args;

        assert_eq!(args.custom_headers.len(), 2);
        assert!(args.custom_headers.iter().any(|h| h.contains("X-Test")));
        assert!(args.custom_headers.iter().any(|h| h.contains("X-Other")));
    }
}
