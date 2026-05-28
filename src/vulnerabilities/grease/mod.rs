// GREASE (Generate Random Extensions And Sustain Extensibility) Testing
// RFC 8701 - Tests server tolerance for reserved GREASE values

mod client_hello;

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{Duration, timeout};

/// GREASE values per RFC 8701
/// These are reserved values that servers MUST ignore
pub const GREASE_CIPHER_SUITES: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub const GREASE_EXTENSIONS: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub const GREASE_SUPPORTED_GROUPS: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// GREASE test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreaseResult {
    pub tolerates_grease: bool,
    pub inconclusive: bool,
    pub direct_grease_test_performed: bool,
    pub issues: Vec<String>,
    pub details: Vec<String>,
    pub tests_performed: Vec<String>,
}

/// GREASE test outcome
#[derive(Debug, Clone)]
pub enum GreaseTestOutcome {
    Tolerated,
    Rejected,
    Inconclusive(String),
}

/// GREASE tester
///
/// Tests if a server properly handles unknown/reserved TLS extensions and values.
/// Servers should ignore unknown extensions gracefully as per RFC 8701.
///
/// GREASE values are reserved values that should be ignored:
/// - Cipher suites: 0x0A0A, 0x1A1A, 0x2A2A, etc.
/// - Extensions: 0x0A0A, 0x1A1A, 0x2A2A, etc.
/// - Supported groups: 0x0A0A, 0x1A1A, 0x2A2A, etc.
pub struct GreaseTester {
    target: Target,
    sni_hostname: Option<String>,
}

impl GreaseTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            sni_hostname: None,
        }
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    /// Test server GREASE tolerance using raw TLS ClientHello injection
    pub async fn test(&self) -> Result<GreaseResult> {
        let mut result = GreaseResult {
            tolerates_grease: false,
            inconclusive: false,
            direct_grease_test_performed: false,
            issues: Vec::new(),
            details: Vec::new(),
            tests_performed: Vec::new(),
        };

        // Baseline connection with standard ClientHello
        let baseline_ok = match self.test_baseline_connection().await {
            Ok(true) => {
                result
                    .details
                    .push("✓ Baseline connection successful".to_string());
                true
            }
            Ok(false) => {
                result.inconclusive = true;
                result
                    .issues
                    .push("Baseline connection failed - cannot test GREASE".to_string());
                return Ok(result);
            }
            Err(e) => {
                result.inconclusive = true;
                result
                    .issues
                    .push(format!("Baseline connection error: {}", e));
                return Ok(result);
            }
        };

        if !baseline_ok {
            return Ok(result);
        }

        // Run each GREASE category test
        self.record_grease_test(
            &mut result,
            "GREASE cipher suites",
            self.test_grease_cipher_suites().await,
        );
        self.record_grease_test(
            &mut result,
            "GREASE extensions",
            self.test_grease_extensions().await,
        );
        self.record_grease_test(
            &mut result,
            "GREASE supported groups",
            self.test_grease_supported_groups().await,
        );
        self.record_grease_test(
            &mut result,
            "Combined GREASE test",
            self.test_combined_grease().await,
        );

        Self::finalize_grease_result(&mut result);

        Ok(result)
    }

    fn finalize_grease_result(result: &mut GreaseResult) {
        if !result.direct_grease_test_performed {
            result.tolerates_grease = false;
            result.inconclusive = true;
            result
                .issues
                .push("No GREASE tests were performed".to_string());
            return;
        }

        let rejected_count = result
            .issues
            .iter()
            .filter(|i| i.contains("rejected") || i.contains("violates"))
            .count();

        let tolerated_count = result
            .details
            .iter()
            .filter(|d| d.starts_with("✓ Server tolerates "))
            .count();

        let inconclusive_count = result
            .details
            .iter()
            .filter(|d| {
                d.contains("test inconclusive") || d.contains("encountered a connection error")
            })
            .count()
            + result
                .tests_performed
                .iter()
                .filter(|t| t.contains("(error:"))
                .count();

        if rejected_count > 0 {
            result.tolerates_grease = false;
            result.inconclusive = false;
        } else if inconclusive_count > 0 {
            result.tolerates_grease = false;
            result.inconclusive = true;
        } else if tolerated_count > 0 {
            result.tolerates_grease = true;
            result.inconclusive = false;
        } else {
            result.tolerates_grease = false;
            result.inconclusive = true;
        }
    }

    /// Record the outcome of a single GREASE category test into the result.
    fn record_grease_test(
        &self,
        result: &mut GreaseResult,
        test_name: &str,
        outcome: Result<GreaseTestOutcome>,
    ) {
        match outcome {
            Ok(test_result) => {
                result.tests_performed.push(test_name.to_string());
                result.direct_grease_test_performed = true;
                match test_result {
                    GreaseTestOutcome::Tolerated => {
                        result
                            .details
                            .push(format!("✓ Server tolerates {}", test_name.to_lowercase()));
                    }
                    GreaseTestOutcome::Rejected => {
                        result.issues.push(format!(
                            "Server rejected {} (violates RFC 8701)",
                            test_name.to_lowercase()
                        ));
                    }
                    GreaseTestOutcome::Inconclusive(reason) => {
                        result
                            .details
                            .push(format!("{} test inconclusive: {}", test_name, reason));
                    }
                }
            }
            Err(e) => {
                result
                    .tests_performed
                    .push(format!("{} (error: {})", test_name, e));
                result.direct_grease_test_performed = true;
                result.details.push(format!(
                    "{} test encountered a connection error: {}",
                    test_name, e
                ));
            }
        }
    }

    /// Test baseline TLS connection (no GREASE)
    async fn test_baseline_connection(&self) -> Result<bool> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(GreaseNoVerifier))
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let sni_host = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        )
        .unwrap_or_else(|| self.target.hostname.clone());
        let server_name = crate::utils::network::server_name_for_hostname(&sni_host)?;

        match timeout(
            Duration::from_secs(10),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Generate comprehensive GREASE report
    pub async fn get_comprehensive_report(&self) -> Result<GreaseReport> {
        let grease_result = self.test().await?;
        let recommendations = self.generate_recommendations(&grease_result);

        Ok(GreaseReport {
            grease_result,
            recommendations,
        })
    }

    /// Generate recommendations
    fn generate_recommendations(&self, result: &GreaseResult) -> Vec<String> {
        let mut recommendations = Vec::new();

        if result.direct_grease_test_performed && result.tolerates_grease {
            recommendations.push(
                "✓ Server properly implements TLS extensibility (RFC 8701 compliant)".to_string(),
            );
        } else if result.direct_grease_test_performed && !result.tolerates_grease {
            recommendations
                .push("Server should properly handle GREASE values per RFC 8701".to_string());
            recommendations.push(
                "Update TLS implementation to ignore unknown cipher suites, extensions, and supported groups".to_string(),
            );
        } else if result.inconclusive {
            recommendations.push(
                "GREASE tolerance could not be determined; results are inconclusive".to_string(),
            );
        }

        if !result.issues.is_empty() {
            recommendations.push(
                "Address the identified issues to improve TLS implementation robustness"
                    .to_string(),
            );
        }

        recommendations
    }
}

/// Comprehensive GREASE report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreaseReport {
    pub grease_result: GreaseResult,
    pub recommendations: Vec<String>,
}

#[derive(Debug)]
struct GreaseNoVerifier;

impl rustls::client::danger::ServerCertVerifier for GreaseNoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
