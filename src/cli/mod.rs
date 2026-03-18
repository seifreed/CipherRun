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
#[command(author, about, long_about = None, disable_version_flag = true)]
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
        self.to_scan_request()
            .validate_common()
            .map_err(anyhow::Error::from)
    }

    pub fn to_scan_request(&self) -> crate::application::ScanRequest {
        crate::application::ScanRequest {
            target: self.target.clone(),
            port: self.port,
            ip: self.ip.clone(),
            scan: crate::application::scan_request::ScanRequestScan {
                protocols: self.scan.protocols,
                each_cipher: self.scan.each_cipher,
                vulnerabilities: self.scan.vulnerabilities,
                headers: self.scan.headers,
                all: self.scan.all,
                full: self.scan.full,
                no_ciphersuites: self.scan.no_ciphersuites,
                no_fallback: self.scan.no_fallback,
                no_compression: self.scan.no_compression,
                no_heartbleed: self.scan.no_heartbleed,
                no_renegotiation: self.scan.no_renegotiation,
                no_check_certificate: self.scan.no_check_certificate,
                show_sigs: self.scan.show_sigs,
                show_groups: self.scan.show_groups,
                no_groups: self.scan.no_groups,
                show_client_cas: self.scan.show_client_cas,
                ssl2: self.scan.ssl2,
                ssl3: self.scan.ssl3,
                tls10: self.scan.tls10,
                tls11: self.scan.tls11,
                tls12: self.scan.tls12,
                tls13: self.scan.tls13,
                tlsall: self.scan.tlsall,
            },
            network: crate::application::scan_request::ScanRequestNetwork {
                ipv4_only: self.network.ipv4_only,
                ipv6_only: self.network.ipv6_only,
                test_all_ips: self.network.test_all_ips,
                first_ip_only: self.network.first_ip_only,
                max_concurrent_ciphers: self.network.max_concurrent_ciphers,
            },
            connection: crate::application::scan_request::ScanRequestConnection {
                socket_timeout: self.connection.socket_timeout,
                connect_timeout: self.connection.connect_timeout,
                sleep: self.connection.sleep,
                max_retries: self.connection.max_retries,
                retry_backoff_ms: self.connection.retry_backoff_ms,
                max_backoff_ms: self.connection.max_backoff_ms,
                no_retry: self.connection.no_retry,
            },
            tls: crate::application::scan_request::ScanRequestTls {
                bugs: self.tls.bugs,
                phone_out: self.tls.phone_out,
                hardfail: self.tls.hardfail,
                sni_name: self.tls.sni_name.clone(),
                mtls_cert: self.tls.mtls_cert.clone(),
                client_key: self.tls.client_key.clone(),
                client_key_password: self.tls.client_key_password.clone(),
                client_certs: self.tls.client_certs.clone(),
            },
            fingerprint: crate::application::scan_request::ScanRequestFingerprint {
                ja3: self.fingerprint.ja3,
                client_hello: self.fingerprint.client_hello,
                ja3_database: self.fingerprint.ja3_database.clone(),
                ja3s: self.fingerprint.ja3s,
                server_hello: self.fingerprint.server_hello,
                ja3s_database: self.fingerprint.ja3s_database.clone(),
                jarm: self.fingerprint.jarm,
                jarm_database: self.fingerprint.jarm_database.clone(),
                client_simulation: self.fingerprint.client_simulation,
            },
            http: crate::application::scan_request::ScanRequestHttp {
                custom_headers: self.http.custom_headers.clone(),
                sneaky: self.http.sneaky,
            },
            starttls: crate::application::scan_request::ScanRequestStarttls {
                protocol: self.starttls.protocol.clone(),
                smtp: self.starttls.smtp,
                imap: self.starttls.imap,
                pop3: self.starttls.pop3,
                ftp: self.starttls.ftp,
                ldap: self.starttls.ldap,
                xmpp: self.starttls.xmpp,
                psql: self.starttls.psql,
                mysql: self.starttls.mysql,
                irc: self.starttls.irc,
                xmpp_server: self.starttls.xmpp_server,
                rdp: self.starttls.rdp,
            },
            ct_logs: crate::application::scan_request::ScanRequestCtLogs {
                enable: self.ct_logs.enable,
            },
        }
    }

    pub fn to_certificate_filters(&self) -> crate::application::CertificateFilters {
        crate::application::CertificateFilters {
            expired: self.cert_filters.filter_expired,
            self_signed: self.cert_filters.filter_self_signed,
            mismatched: self.cert_filters.filter_mismatched,
            revoked: self.cert_filters.filter_revoked,
            untrusted: self.cert_filters.filter_untrusted,
        }
    }

    /// Detect which STARTTLS protocol is requested
    pub fn starttls_protocol(&self) -> Option<crate::starttls::StarttlsProtocol> {
        self.to_scan_request().starttls_protocol()
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
        self.to_scan_request().protocols_to_test()
    }

    /// Build a RetryConfig from CLI arguments
    ///
    /// Returns None if retry is disabled (--no-retry or --max-retries 0)
    /// Otherwise returns a configured RetryConfig with the specified parameters
    pub fn retry_config(&self) -> Option<crate::utils::retry::RetryConfig> {
        self.to_scan_request().retry_config()
    }

    /// Check if any certificate validation filters are active
    ///
    /// Returns true if at least one certificate filter flag is set,
    /// indicating that scan results should be filtered based on certificate validation status
    pub fn has_certificate_filters(&self) -> bool {
        self.cert_filters.has_filters()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_conflicting_ip_flags() {
        let mut args = Args::default();
        args.network.test_all_ips = true;
        args.network.first_ip_only = true;
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_ip_with_test_all_ips_conflict() {
        let mut args = Args::default();
        args.ip = Some("127.0.0.1".to_string());
        args.network.test_all_ips = true;
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_ip_with_first_ip_only_conflict() {
        let mut args = Args::default();
        args.ip = Some("127.0.0.1".to_string());
        args.network.first_ip_only = true;
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_run_default_suite_flags() {
        let args = Args::default();
        assert!(args.run_default_suite());

        let mut args = Args::default();
        args.scan.protocols = true;
        assert!(!args.run_default_suite());
    }

    #[test]
    fn test_vulnerability_flags() {
        let args = Args::default();
        assert!(!args.test_vulnerabilities());

        let mut args = Args::default();
        args.scan.breach = true;
        assert!(args.test_vulnerabilities());
    }

    #[test]
    fn test_effective_sni() {
        let mut args = Args::default();
        assert_eq!(args.effective_sni("example.com"), "example.com");

        args.tls.sni_name = Some("custom.test".to_string());
        assert_eq!(args.effective_sni("example.com"), "custom.test");
    }

    #[test]
    fn test_protocols_to_test_flags() {
        let mut args = Args::default();
        args.scan.ssl2 = true;
        args.scan.tls13 = true;
        let protocols = args.protocols_to_test().unwrap();
        assert_eq!(
            protocols,
            vec![
                crate::protocols::Protocol::SSLv2,
                crate::protocols::Protocol::TLS13
            ]
        );

        let mut args = Args::default();
        args.scan.tlsall = true;
        let protocols = args.protocols_to_test().unwrap();
        assert_eq!(
            protocols,
            vec![
                crate::protocols::Protocol::TLS10,
                crate::protocols::Protocol::TLS11,
                crate::protocols::Protocol::TLS12,
                crate::protocols::Protocol::TLS13,
            ]
        );

        let args = Args::default();
        assert!(args.protocols_to_test().is_none());
    }

    #[test]
    fn test_retry_config() {
        let mut args = Args::default();
        args.connection.no_retry = true;
        assert!(args.retry_config().is_none());

        let mut args = Args::default();
        args.connection.max_retries = 0;
        assert!(args.retry_config().is_none());

        let mut args = Args::default();
        args.connection.max_retries = 5;
        args.connection.retry_backoff_ms = 250;
        args.connection.max_backoff_ms = 2000;
        let cfg = args.retry_config().expect("should return retry config");
        assert_eq!(cfg.max_retries, 5);
        assert_eq!(cfg.initial_backoff, std::time::Duration::from_millis(250));
        assert_eq!(cfg.max_backoff, std::time::Duration::from_millis(2000));
    }

    #[test]
    fn test_has_certificate_filters() {
        let mut args = Args::default();
        assert!(!args.has_certificate_filters());

        args.cert_filters.filter_expired = true;
        assert!(args.has_certificate_filters());
    }

    #[test]
    fn test_run_default_suite_disabled_by_client_simulation() {
        let mut args = Args::default();
        args.fingerprint.client_simulation = true;
        assert!(!args.run_default_suite());
    }
}
