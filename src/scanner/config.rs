//! Domain-specific configuration objects extracted from CLI Args.
//!
//! These provide focused interfaces for scanner phases, following the
//! Interface Segregation Principle. Each config struct extracts only
//! the fields needed for its specific domain, avoiding coupling to
//! the full Args struct.

use std::time::Duration;

use crate::protocols::Protocol;
use crate::starttls::StarttlsProtocol;

/// Configuration for protocol testing
///
/// Contains only the fields needed by ProtocolTester and ProtocolPhase.
#[derive(Debug, Clone)]
pub struct ProtocolTestConfig {
    /// Specific protocols to test (None = test all)
    pub protocols: Option<Vec<Protocol>>,
    /// STARTTLS protocol for application-layer negotiation
    pub starttls: Option<StarttlsProtocol>,
    /// Custom SNI hostname
    pub sni_name: Option<String>,
    /// Enable OpenSSL bug workarounds
    pub bugs_mode: bool,
    /// Connection timeout
    pub timeout: Duration,
}

impl ProtocolTestConfig {
    /// Create configuration from CLI Args
    pub fn from_args(args: &crate::cli::Args) -> Self {
        Self {
            protocols: args.protocols_to_test(),
            starttls: args.starttls_protocol(),
            sni_name: args.tls.sni_name.clone(),
            bugs_mode: args.tls.bugs,
            timeout: Duration::from_secs(args.connection.socket_timeout.unwrap_or(10)),
        }
    }
}

/// Configuration for cipher testing
///
/// Contains only the fields needed by CipherTester and CipherPhase.
#[derive(Debug, Clone)]
pub struct CipherTestConfig {
    /// Test all cipher suites (not just common ones)
    pub test_all_ciphers: bool,
    /// Maximum concurrent cipher tests
    pub max_concurrent: usize,
    /// Connection timeout
    pub timeout: Duration,
}

impl CipherTestConfig {
    /// Default maximum concurrent cipher tests
    const DEFAULT_MAX_CONCURRENT: usize = 10;

    /// Create configuration from CLI Args
    pub fn from_args(args: &crate::cli::Args) -> Self {
        let max_concurrent = if args.network.max_concurrent_ciphers == 0 {
            Self::DEFAULT_MAX_CONCURRENT
        } else {
            args.network.max_concurrent_ciphers
        };

        Self {
            test_all_ciphers: args.scan.each_cipher,
            max_concurrent,
            timeout: Duration::from_secs(args.connection.socket_timeout.unwrap_or(10)),
        }
    }
}

/// Configuration for certificate analysis
///
/// Contains only the fields needed by certificate validation and analysis.
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    /// Check certificate revocation status (OCSP, CRL)
    pub check_revocation: bool,
    /// Check Certificate Transparency logs
    pub check_ct_logs: bool,
    /// Hard fail on revocation check errors
    pub hardfail: bool,
}

impl CertificateConfig {
    /// Create configuration from CLI Args
    pub fn from_args(args: &crate::cli::Args) -> Self {
        Self {
            check_revocation: args.tls.phone_out,
            check_ct_logs: args.ct_logs.enable,
            hardfail: args.tls.hardfail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_config_defaults() {
        let args = crate::cli::Args::default();
        let config = ProtocolTestConfig::from_args(&args);

        assert!(config.protocols.is_none());
        assert!(config.starttls.is_none());
        assert!(config.sni_name.is_none());
        assert!(!config.bugs_mode);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_cipher_config_defaults() {
        let args = crate::cli::Args::default();
        let config = CipherTestConfig::from_args(&args);

        assert!(!config.test_all_ciphers);
        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_certificate_config_defaults() {
        let args = crate::cli::Args::default();
        let config = CertificateConfig::from_args(&args);

        assert!(!config.check_revocation);
        assert!(!config.check_ct_logs);
        assert!(!config.hardfail);
    }
}
