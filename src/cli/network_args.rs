// Network configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;

pub const DEFAULT_MAX_PARALLEL: usize = 20;
pub const DEFAULT_MAX_CONCURRENT_CIPHERS: usize = 10;

/// Network configuration options
///
/// This struct contains all arguments related to network configuration,
/// including IP version selection, proxy settings, DNS resolvers,
/// and multi-IP scanning behavior.
#[derive(Args, Debug, Clone)]
pub struct NetworkArgs {
    /// Use only IPv4
    #[arg(short = '4')]
    pub ipv4_only: bool,

    /// Use only IPv6
    #[arg(short = '6')]
    pub ipv6_only: bool,

    /// Proxy (host:port)
    #[arg(long = "proxy", value_name = "HOST:PORT")]
    pub proxy: Option<String>,

    /// Custom DNS resolvers (comma-separated: 8.8.8.8,1.1.1.1)
    #[arg(long = "resolvers", value_delimiter = ',')]
    pub resolvers: Vec<String>,

    /// Test all IP addresses resolved for hostname (default behavior when multiple IPs found)
    /// When a hostname resolves to multiple IPs (load balancers, Anycast), all IPs are tested
    /// by default and results are aggregated using worst-case approach. Use --first-ip-only
    /// to scan only the first IP for faster results.
    #[arg(long = "test-all-ips")]
    pub test_all_ips: bool,

    /// Scan only the first resolved IP address (faster, single IP mode)
    /// Use this flag to explicitly scan only the first IP when you want faster results,
    /// especially for hosts with multiple load balancer IPs. By default, all IPs are scanned.
    #[arg(long = "first-ip-only")]
    pub first_ip_only: bool,

    /// Scan all resolved IP addresses for hostname (Anycast detection)
    /// Tests each A and AAAA record individually to detect Anycast deployments
    #[arg(long = "scan-all-ips", alias = "sa")]
    pub scan_all_ips: bool,

    /// Parallel testing mode
    #[arg(long = "parallel")]
    pub parallel: bool,

    /// Maximum parallel connections
    #[arg(
        long = "max-parallel",
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_PARALLEL
    )]
    pub max_parallel: usize,

    /// Maximum concurrent cipher tests per protocol (default: 10)
    /// Lower values reduce network load and prevent "Network is down" errors
    #[arg(
        long = "max-concurrent-ciphers",
        value_name = "NUM",
        default_value_t = DEFAULT_MAX_CONCURRENT_CIPHERS
    )]
    pub max_concurrent_ciphers: usize,
}

impl Default for NetworkArgs {
    fn default() -> Self {
        Self {
            ipv4_only: false,
            ipv6_only: false,
            proxy: None,
            resolvers: Vec::new(),
            test_all_ips: false,
            first_ip_only: false,
            scan_all_ips: false,
            parallel: false,
            max_parallel: DEFAULT_MAX_PARALLEL,
            max_concurrent_ciphers: DEFAULT_MAX_CONCURRENT_CIPHERS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: NetworkArgs,
    }

    #[test]
    fn test_network_args_defaults_from_clap() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(!args.ipv4_only);
        assert!(!args.ipv6_only);
        assert!(args.proxy.is_none());
        assert!(args.resolvers.is_empty());
        assert!(!args.test_all_ips);
        assert!(!args.first_ip_only);
        assert!(!args.scan_all_ips);
        assert!(!args.parallel);
        assert_eq!(args.max_parallel, 20);
        assert_eq!(args.max_concurrent_ciphers, 10);
    }

    #[test]
    fn test_network_args_custom_values() {
        let parsed = TestCli::parse_from([
            "test",
            "--resolvers",
            "8.8.8.8,1.1.1.1",
            "--max-parallel",
            "7",
            "--max-concurrent-ciphers",
            "3",
            "--parallel",
            "--first-ip-only",
        ]);
        let args = parsed.args;

        assert_eq!(
            args.resolvers,
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
        assert_eq!(args.max_parallel, 7);
        assert_eq!(args.max_concurrent_ciphers, 3);
        assert!(args.parallel);
        assert!(args.first_ip_only);
    }

    #[test]
    fn test_network_args_ip_version_flags() {
        let parsed = TestCli::parse_from(["test", "-4", "-6"]);
        let args = parsed.args;

        assert!(args.ipv4_only);
        assert!(args.ipv6_only);
    }
}
