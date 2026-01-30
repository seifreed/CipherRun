// TLS and OpenSSL configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;
use std::path::PathBuf;

/// TLS and OpenSSL configuration options
///
/// This struct contains all arguments related to TLS/SSL configuration,
/// including OpenSSL settings, certificate handling, SNI configuration,
/// and mTLS client authentication.
#[derive(Args, Debug, Clone, Default)]
pub struct TlsConfigArgs {
    // ============ OpenSSL Configuration ============
    /// OpenSSL binary path
    #[arg(long = "openssl", value_name = "PATH")]
    pub openssl_path: Option<PathBuf>,

    /// OpenSSL timeout in seconds
    #[arg(long = "openssl-timeout", value_name = "SECONDS")]
    pub openssl_timeout: Option<u64>,

    /// Use OpenSSL native instead of sockets
    #[arg(long = "ssl-native")]
    pub ssl_native: bool,

    /// Enable OpenSSL bugs workarounds
    #[arg(long = "bugs")]
    pub bugs: bool,

    /// List local OpenSSL ciphers and exit
    #[arg(long = "local")]
    pub local: bool,

    // ============ Certificate Handling ============
    /// Enable phone-out (CRL, OCSP checks)
    #[arg(long = "phone-out")]
    pub phone_out: bool,

    /// Hard fail on revocation check errors (requires --phone-out)
    #[arg(long = "hardfail", alias = "hf")]
    pub hardfail: bool,

    /// Additional CA file or directory
    #[arg(long = "add-ca", value_name = "PATH")]
    pub add_ca: Option<PathBuf>,

    // ============ mTLS Client Authentication ============
    /// Client certificate for mTLS (PEM file with cert and unencrypted key)
    #[arg(long = "mtls", value_name = "FILE")]
    pub mtls_cert: Option<PathBuf>,

    /// Client private key file for mTLS
    #[arg(long = "pk", value_name = "FILE")]
    pub client_key: Option<PathBuf>,

    /// Password for client private key
    #[arg(long = "pkpass", value_name = "PASSWORD")]
    pub client_key_password: Option<String>,

    /// Client certificate file for mTLS (can be different from --pk)
    #[arg(long = "certs", value_name = "FILE")]
    pub client_certs: Option<PathBuf>,

    // ============ SNI Configuration ============
    /// Custom SNI hostname (for CDN/vhost testing)
    #[arg(long = "sni-name", value_name = "NAME")]
    pub sni_name: Option<String>,

    /// Use random SNI when scanning IP addresses
    /// Generates random valid-looking SNI hostnames
    #[arg(long = "random-sni", alias = "rs")]
    pub random_sni: bool,

    /// Use reverse PTR lookup for SNI when scanning IPs
    /// Performs reverse DNS to determine appropriate SNI
    #[arg(long = "reverse-ptr-sni", alias = "rps")]
    pub reverse_ptr_sni: bool,
}
