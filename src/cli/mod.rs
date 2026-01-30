// CLI module - Command line interface and argument parsing
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Parser;
use std::path::PathBuf;

// Sub-modules for organized CLI arguments
mod api_server_args;
mod certificate_filter_args;
mod compliance_args;
mod connection_args;
mod ct_logs_args;
mod database_args;
mod fingerprint_args;
mod http_args;
mod monitoring_args;
mod network_args;
mod output_args;
mod scan_args;
mod starttls_args;
mod tls_config_args;

// Re-export sub-structs
pub use api_server_args::ApiServerArgs;
pub use certificate_filter_args::CertificateFilterArgs;
pub use compliance_args::ComplianceArgs;
pub use connection_args::ConnectionArgs;
pub use ct_logs_args::CtLogsArgs;
pub use database_args::DatabaseArgs;
pub use fingerprint_args::FingerprintArgs;
pub use http_args::HttpArgs;
pub use monitoring_args::MonitoringArgs;
pub use network_args::NetworkArgs;
pub use output_args::OutputArgs;
pub use scan_args::ScanArgs;
pub use starttls_args::StarttlsArgs;
pub use tls_config_args::TlsConfigArgs;

/// CipherRun - Fast, modular TLS/SSL security scanner
///
/// This is the main CLI arguments struct that composes all domain-specific
/// configuration sub-structs using clap's #[command(flatten)] attribute.
///
/// The Args struct is organized into logical domains:
/// - Target specification and input
/// - STARTTLS protocol options (StarttlsArgs)
/// - Database operations (DatabaseArgs)
/// - Monitoring daemon (MonitoringArgs)
/// - API server (ApiServerArgs)
/// - TLS fingerprinting (FingerprintArgs)
/// - Output formats (OutputArgs)
/// - Core scanning (ScanArgs)
/// - Compliance frameworks (ComplianceArgs)
/// - CT logs streaming (CtLogsArgs)
/// - Network settings (NetworkArgs)
/// - Connection and timeout settings (ConnectionArgs)
/// - TLS/SSL configuration (TlsConfigArgs)
/// - HTTP settings (HttpArgs)
/// - Certificate filters (CertificateFilterArgs)
/// - Analytics and database queries
#[derive(Parser, Debug, Clone, Default)]
#[command(author, version, about, long_about = None)]
#[command(name = "cipherrun")]
#[command(about = "Fast, modular TLS/SSL security scanner", long_about = None)]
pub struct Args {
    // ============ Target Specification and Input ============
    /// Target URI (host:port or URL)
    #[arg(value_name = "URI")]
    pub target: Option<String>,

    /// Input file with multiple targets
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub input_file: Option<PathBuf>,

    /// Test MX records for a domain (mail servers)
    #[arg(long = "mx", value_name = "DOMAIN")]
    pub mx_domain: Option<String>,

    /// Port to test
    #[arg(long = "port", value_name = "PORT", id = "target_port")]
    pub port: Option<u16>,

    /// Specific IP to test
    #[arg(long = "ip", value_name = "IP")]
    pub ip: Option<String>,

    // ============ STARTTLS Protocol Options ============
    #[command(flatten)]
    pub starttls: StarttlsArgs,

    // ============ Database Operations ============
    #[command(flatten)]
    pub database: DatabaseArgs,

    // ============ Certificate Monitoring ============
    #[command(flatten)]
    pub monitoring: MonitoringArgs,

    // ============ REST API Server ============
    #[command(flatten)]
    pub api_server: ApiServerArgs,

    // ============ TLS Fingerprinting ============
    #[command(flatten)]
    pub fingerprint: FingerprintArgs,

    // ============ Output Formats and Display ============
    #[command(flatten)]
    pub output: OutputArgs,

    // ============ Core Scanning Options ============
    #[command(flatten)]
    pub scan: ScanArgs,

    // ============ Compliance Framework Engine ============
    #[command(flatten)]
    pub compliance: ComplianceArgs,

    // ============ Certificate Transparency Logs ============
    #[command(flatten)]
    pub ct_logs: CtLogsArgs,

    // ============ Network Configuration ============
    #[command(flatten)]
    pub network: NetworkArgs,

    // ============ Connection and Timeout Settings ============
    #[command(flatten)]
    pub connection: ConnectionArgs,

    // ============ TLS/SSL Configuration ============
    #[command(flatten)]
    pub tls: TlsConfigArgs,

    // ============ HTTP Settings ============
    #[command(flatten)]
    pub http: HttpArgs,

    // ============ Certificate Validation Filters ============
    #[command(flatten)]
    pub cert_filters: CertificateFilterArgs,

    // ============ Database Analytics ============
    /// Compare two scans (format: SCAN_ID_1:SCAN_ID_2)
    #[arg(long = "compare", value_name = "SCAN_ID_1:SCAN_ID_2")]
    pub compare: Option<String>,

    /// Detect changes for hostname in last N days (format: HOSTNAME:PORT:DAYS)
    #[arg(long = "changes", value_name = "HOSTNAME:PORT:DAYS")]
    pub changes: Option<String>,

    /// Analyze trends for hostname in last N days (format: HOSTNAME:PORT:DAYS)
    #[arg(long = "trends", value_name = "HOSTNAME:PORT:DAYS")]
    pub trends: Option<String>,

    /// Generate dashboard data for hostname (format: HOSTNAME:PORT:DAYS)
    #[arg(long = "dashboard", value_name = "HOSTNAME:PORT:DAYS")]
    pub dashboard: Option<String>,

    /// Display version information and exit
    #[arg(long = "version", short = 'V')]
    pub version: bool,
}

impl Args {
    /// Validate CLI arguments for mutual exclusivity and logical consistency
    ///
    /// Returns an error if conflicting flags are used together
    pub fn validate(&self) -> anyhow::Result<()> {
        // Check for conflicting IP scanning flags
        if self.network.test_all_ips && self.network.first_ip_only {
            anyhow::bail!(
                "Cannot use --test-all-ips and --first-ip-only together. Choose one scanning mode."
            );
        }

        if self.ip.is_some() && self.network.test_all_ips {
            anyhow::bail!(
                "Cannot use --ip with --test-all-ips. The --ip flag specifies a single IP to scan."
            );
        }

        if self.ip.is_some() && self.network.first_ip_only {
            anyhow::bail!(
                "Cannot use --ip with --first-ip-only. The --ip flag already specifies a single IP to scan."
            );
        }

        Ok(())
    }

    /// Detect which STARTTLS protocol is requested
    pub fn starttls_protocol(&self) -> Option<crate::starttls::StarttlsProtocol> {
        self.starttls.starttls_protocol()
    }

    /// Check if we should run the default test suite
    pub fn run_default_suite(&self) -> bool {
        !self.scan.protocols
            && !self.scan.each_cipher
            && !self.scan.cipher_per_proto
            && !self.scan.categories
            && !self.scan.forward_secrecy
            && !self.scan.server_defaults
            && !self.scan.server_preference
            && !self.scan.headers
            && !self.scan.vulnerabilities
            && !self.scan.heartbleed
            && !self.fingerprint.client_simulation
            && !self.scan.full
    }

    /// Check if vulnerability testing is enabled
    pub fn test_vulnerabilities(&self) -> bool {
        self.scan.vulnerabilities
            || self.scan.heartbleed
            || self.scan.ccs
            || self.scan.ticketbleed
            || self.scan.robot
            || self.scan.renegotiation
            || self.scan.crime
            || self.scan.breach
            || self.scan.poodle
            || self.scan.fallback
            || self.scan.sweet32
            || self.scan.beast
            || self.scan.lucky13
            || self.scan.freak
            || self.scan.logjam
            || self.scan.drown
            || self.scan.early_data
            || self.scan.full
    }

    /// Get the SNI hostname to use (custom or default)
    pub fn effective_sni(&self, default_hostname: &str) -> String {
        self.tls
            .sni_name
            .clone()
            .unwrap_or_else(|| default_hostname.to_string())
    }

    /// Get list of protocols to test based on flags
    pub fn protocols_to_test(&self) -> Option<Vec<crate::protocols::Protocol>> {
        use crate::protocols::Protocol;

        // If specific protocol flags are set, only test those
        if self.scan.ssl2
            || self.scan.ssl3
            || self.scan.tls10
            || self.scan.tls11
            || self.scan.tls12
            || self.scan.tls13
        {
            let mut protocols = Vec::new();
            if self.scan.ssl2 {
                protocols.push(Protocol::SSLv2);
            }
            if self.scan.ssl3 {
                protocols.push(Protocol::SSLv3);
            }
            if self.scan.tls10 {
                protocols.push(Protocol::TLS10);
            }
            if self.scan.tls11 {
                protocols.push(Protocol::TLS11);
            }
            if self.scan.tls12 {
                protocols.push(Protocol::TLS12);
            }
            if self.scan.tls13 {
                protocols.push(Protocol::TLS13);
            }
            return Some(protocols);
        }

        // If --tlsall is set, skip SSL protocols
        if self.scan.tlsall {
            return Some(vec![
                Protocol::TLS10,
                Protocol::TLS11,
                Protocol::TLS12,
                Protocol::TLS13,
            ]);
        }

        // Otherwise test all protocols
        None
    }

    /// Build a RetryConfig from CLI arguments
    ///
    /// Returns None if retry is disabled (--no-retry or --max-retries 0)
    /// Otherwise returns a configured RetryConfig with the specified parameters
    pub fn retry_config(&self) -> Option<crate::utils::retry::RetryConfig> {
        if self.connection.no_retry || self.connection.max_retries == 0 {
            return None;
        }

        Some(crate::utils::retry::RetryConfig::new(
            self.connection.max_retries,
            std::time::Duration::from_millis(self.connection.retry_backoff_ms),
            std::time::Duration::from_millis(self.connection.max_backoff_ms),
        ))
    }

    /// Check if any certificate validation filters are active
    ///
    /// Returns true if at least one certificate filter flag is set,
    /// indicating that scan results should be filtered based on certificate validation status
    pub fn has_certificate_filters(&self) -> bool {
        self.cert_filters.has_filters()
    }
}
