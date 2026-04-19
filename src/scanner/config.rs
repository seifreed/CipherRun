//! Domain-specific configuration objects extracted from CLI Args.
//!
//! These provide focused interfaces for scanner phases, following the
//! Interface Segregation Principle. Each config struct extracts only
//! the fields needed for its specific domain, avoiding coupling to
//! the full scan request contract.

use std::time::Duration;

use crate::application::ScanRequest;
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
    /// Create configuration from ScanRequest
    pub fn from_request(request: &ScanRequest) -> Self {
        Self {
            protocols: request.protocols_to_test(),
            starttls: request.starttls_protocol(),
            sni_name: request.tls.sni_name.clone(),
            bugs_mode: request.tls.bugs,
            timeout: Duration::from_secs(request.connection.socket_timeout.unwrap_or(10)),
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

    /// Create configuration from ScanRequest
    pub fn from_request(request: &ScanRequest) -> Self {
        let max_concurrent = if request.network.max_concurrent_ciphers == 0 {
            Self::DEFAULT_MAX_CONCURRENT
        } else {
            request.network.max_concurrent_ciphers
        };

        Self {
            test_all_ciphers: request.scan.ciphers.each_cipher,
            max_concurrent,
            timeout: Duration::from_secs(request.connection.socket_timeout.unwrap_or(10)),
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
    /// Create configuration from ScanRequest
    pub fn from_request(request: &ScanRequest) -> Self {
        Self {
            check_revocation: request.tls.phone_out,
            check_ct_logs: request.ct_logs.enable,
            hardfail: request.tls.hardfail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_config_defaults() {
        let request = ScanRequest::default();
        let config = ProtocolTestConfig::from_request(&request);

        assert!(config.protocols.is_none());
        assert!(config.starttls.is_none());
        assert!(config.sni_name.is_none());
        assert!(!config.bugs_mode);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_cipher_config_defaults() {
        let request = ScanRequest::default();
        let config = CipherTestConfig::from_request(&request);

        assert!(!config.test_all_ciphers);
        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_certificate_config_defaults() {
        let request = ScanRequest::default();
        let config = CertificateConfig::from_request(&request);

        assert!(!config.check_revocation);
        assert!(!config.check_ct_logs);
        assert!(!config.hardfail);
    }

    #[test]
    fn test_protocol_config_with_flags() {
        let mut request = ScanRequest::default();
        request.tls.bugs = true;
        request.tls.sni_name = Some("sni.example".to_string());
        request.starttls.smtp = true;
        request.connection.socket_timeout = Some(22);

        let config = ProtocolTestConfig::from_request(&request);
        assert!(config.bugs_mode);
        assert_eq!(config.sni_name.as_deref(), Some("sni.example"));
        assert!(config.starttls.is_some());
        assert_eq!(config.timeout, Duration::from_secs(22));
    }

    #[test]
    fn test_cipher_config_custom_max() {
        let mut request = ScanRequest::default();
        request.network.max_concurrent_ciphers = 3;
        request.scan.ciphers.each_cipher = true;
        request.connection.socket_timeout = Some(15);

        let config = CipherTestConfig::from_request(&request);
        assert!(config.test_all_ciphers);
        assert_eq!(config.max_concurrent, 3);
        assert_eq!(config.timeout, Duration::from_secs(15));
    }
}
