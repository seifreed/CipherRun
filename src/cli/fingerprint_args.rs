// TLS fingerprinting configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::{ArgAction, Args};
use std::path::PathBuf;

/// TLS fingerprinting options (JA3, JA3S, JARM)
///
/// This struct contains all arguments related to TLS fingerprinting,
/// including JA3 client fingerprinting, JA3S server fingerprinting,
/// JARM active fingerprinting, and client simulation.
#[derive(Args, Debug, Clone, Default)]
pub struct FingerprintArgs {
    /// Calculate JA3 TLS client fingerprint (default: enabled, use --ja3=false to disable)
    #[arg(long = "ja3", default_value_t = true, action = ArgAction::Set)]
    pub ja3: bool,

    /// Include full ClientHello in JSON output
    #[arg(long = "client-hello", alias = "ch")]
    pub client_hello: bool,

    /// Path to custom JA3 signature database (JSON format)
    #[arg(long = "ja3-db", value_name = "FILE")]
    pub ja3_database: Option<PathBuf>,

    /// Calculate JA3S TLS server fingerprint (default: enabled, use --ja3s=false to disable)
    #[arg(long = "ja3s", default_value_t = true, action = ArgAction::Set)]
    pub ja3s: bool,

    /// Include full ServerHello in JSON output
    #[arg(long = "server-hello", alias = "sh")]
    pub server_hello: bool,

    /// Path to custom JA3S signature database (JSON format)
    #[arg(long = "ja3s-db", value_name = "FILE")]
    pub ja3s_database: Option<PathBuf>,

    /// Calculate JARM TLS server fingerprint (default: enabled, use --jarm=false to disable)
    #[arg(long = "jarm", default_value_t = true, action = ArgAction::Set)]
    pub jarm: bool,

    /// Path to custom JARM signature database (JSON format)
    #[arg(long = "jarm-db", value_name = "FILE")]
    pub jarm_database: Option<PathBuf>,

    /// Test client simulations
    #[arg(short = 'c', long = "client-simulation")]
    pub client_simulation: bool,

    /// Export Client/Server Hello raw data in specified format
    /// Valid formats: hex, base64, hexdump, binary
    #[arg(long = "export-hello", value_name = "FORMAT")]
    pub export_hello: Option<String>,
}
