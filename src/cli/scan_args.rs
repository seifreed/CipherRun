// Core scanning configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::{ArgAction, Args};

/// Core TLS/SSL scanning options
///
/// This struct contains all arguments related to protocol testing,
/// cipher suite enumeration, vulnerability scanning, certificate analysis,
/// and server configuration testing.
#[derive(Args, Debug, Clone, Default)]
pub struct ScanArgs {
    /// Test all protocols
    #[arg(short = 'p', long = "protocols")]
    pub protocols: bool,

    /// Test all ciphers
    #[arg(short = 'e', long = "each-cipher")]
    pub each_cipher: bool,

    /// Test ciphers per protocol
    #[arg(short = 'E', long = "cipher-per-proto")]
    pub cipher_per_proto: bool,

    /// Test standard cipher categories
    #[arg(short = 's', long = "std")]
    pub categories: bool,

    /// Test forward secrecy
    #[arg(short = 'F', long = "fs")]
    pub forward_secrecy: bool,

    /// Test server defaults
    #[arg(short = 'S', long = "server-defaults")]
    pub server_defaults: bool,

    /// Test server cipher preference
    #[arg(short = 'P', long = "server-preference")]
    pub server_preference: bool,

    /// Test HTTP headers
    #[arg(short = 'h', long = "headers")]
    pub headers: bool,

    /// Test all vulnerabilities
    #[arg(short = 'U', long = "vulnerable")]
    pub vulnerabilities: bool,

    /// Test for Heartbleed
    #[arg(short = 'H', long = "heartbleed")]
    pub heartbleed: bool,

    /// Test for CCS Injection
    #[arg(short = 'I', long = "ccs")]
    pub ccs: bool,

    /// Test for Ticketbleed
    #[arg(short = 'T', long = "ticketbleed")]
    pub ticketbleed: bool,

    /// Test for ROBOT
    #[arg(long = "robot")]
    pub robot: bool,

    /// Test for renegotiation vulnerabilities
    #[arg(short = 'R', long = "renegotiation")]
    pub renegotiation: bool,

    /// Test for CRIME
    #[arg(short = 'C', long = "crime")]
    pub crime: bool,

    /// Test for BREACH
    #[arg(short = 'B', long = "breach")]
    pub breach: bool,

    /// Test for POODLE
    #[arg(short = 'O', long = "poodle")]
    pub poodle: bool,

    /// Test for TLS_FALLBACK_SCSV
    #[arg(short = 'Z', long = "tls-fallback")]
    pub fallback: bool,

    /// Test for SWEET32
    #[arg(short = 'W', long = "sweet32")]
    pub sweet32: bool,

    /// Test for BEAST
    #[arg(short = 'A', long = "beast")]
    pub beast: bool,

    /// Test for LUCKY13
    #[arg(short = 'L', long = "lucky13")]
    pub lucky13: bool,

    /// Test for FREAK
    #[arg(long = "freak")]
    pub freak: bool,

    /// Test for LOGJAM
    #[arg(short = 'J', long = "logjam")]
    pub logjam: bool,

    /// Test for DROWN
    #[arg(short = 'D', long = "drown")]
    pub drown: bool,

    /// Test for 0-RTT / Early Data replay attacks (TLS 1.3)
    #[arg(long = "early-data")]
    pub early_data: bool,

    /// Run full test suite
    #[arg(short = '9', long = "full")]
    pub full: bool,

    /// Run all tests (default: enabled, use --all=false to disable)
    #[arg(short = 'a', long = "all", default_value_t = true, action = ArgAction::Set)]
    pub all: bool,

    /// Test only SSLv2
    #[arg(long = "ssl2")]
    pub ssl2: bool,

    /// Test only SSLv3
    #[arg(long = "ssl3")]
    pub ssl3: bool,

    /// Test only TLS 1.0
    #[arg(long = "tls10")]
    pub tls10: bool,

    /// Test only TLS 1.1
    #[arg(long = "tls11")]
    pub tls11: bool,

    /// Test only TLS 1.2
    #[arg(long = "tls12")]
    pub tls12: bool,

    /// Test only TLS 1.3
    #[arg(long = "tls13")]
    pub tls13: bool,

    /// Test all TLS protocols (skip SSLv2/SSLv3)
    #[arg(long = "tlsall")]
    pub tlsall: bool,

    /// Enumerate server signature algorithms
    #[arg(long = "show-sigs")]
    pub show_sigs: bool,

    /// Enumerate key exchange groups (curves, DH groups)
    #[arg(long = "show-groups")]
    pub show_groups: bool,

    /// Show list of CAs acceptable for client certificates
    #[arg(long = "show-client-cas")]
    pub show_client_cas: bool,

    /// List all ciphers supported by CipherRun and exit
    #[arg(long = "show-ciphers")]
    pub show_ciphers: bool,

    /// Show the full certificate chain (not just leaf)
    #[arg(long = "show-certificates")]
    pub show_certificates: bool,

    /// Skip cipher suite enumeration (faster, only protocols + vulnerabilities)
    #[arg(long = "no-ciphersuites")]
    pub no_ciphersuites: bool,

    /// Skip TLS Fallback SCSV check
    #[arg(long = "no-fallback")]
    pub no_fallback: bool,

    /// Hide EC curve names and DHE key lengths
    #[arg(long = "no-cipher-details")]
    pub no_cipher_details: bool,

    /// Display OCSP stapling status
    #[arg(long = "ocsp")]
    pub ocsp: bool,

    /// Skip key exchange groups enumeration
    #[arg(long = "no-groups")]
    pub no_groups: bool,

    /// Skip TLS compression check (CRIME)
    #[arg(long = "no-compression")]
    pub no_compression: bool,

    /// Skip Heartbleed vulnerability check
    #[arg(long = "no-heartbleed")]
    pub no_heartbleed: bool,

    /// Skip renegotiation vulnerability check
    #[arg(long = "no-renegotiation")]
    pub no_renegotiation: bool,

    /// Skip certificate validation warnings
    #[arg(long = "no-check-certificate")]
    pub no_check_certificate: bool,

    /// Disable SSL Labs rating
    #[arg(long = "disable-rating")]
    pub disable_rating: bool,

    /// Fast mode - skip some tests for speed
    #[arg(long = "fast")]
    pub fast: bool,

    /// Use pre-handshake mode for fast certificate retrieval (early termination)
    /// Disconnects after ServerHello without completing full handshake (2-3x faster)
    /// Only works with TLS 1.0-1.2
    #[arg(long = "pre-handshake", alias = "ps")]
    pub pre_handshake: bool,

    /// Show probe status (success/failure) for each target
    /// Displays connection status with timing information
    #[arg(long = "probe-status", alias = "tps")]
    pub probe_status: bool,
}
