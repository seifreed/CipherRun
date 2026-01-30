// Network configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;

/// Network configuration options
///
/// This struct contains all arguments related to network configuration,
/// including IP version selection, proxy settings, DNS resolvers,
/// and multi-IP scanning behavior.
#[derive(Args, Debug, Clone, Default)]
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
    #[arg(long = "max-parallel", value_name = "NUM", default_value = "20")]
    pub max_parallel: usize,

    /// Maximum concurrent cipher tests per protocol (default: 10)
    /// Lower values reduce network load and prevent "Network is down" errors
    #[arg(
        long = "max-concurrent-ciphers",
        value_name = "NUM",
        default_value = "10"
    )]
    pub max_concurrent_ciphers: usize,
}
