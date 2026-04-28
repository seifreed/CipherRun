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
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Once;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_grease_values_defined() {
        assert!(!GREASE_CIPHER_SUITES.is_empty());
        assert!(!GREASE_EXTENSIONS.is_empty());
        assert!(!GREASE_SUPPORTED_GROUPS.is_empty());

        // Check that GREASE values follow the RFC 8701 pattern
        assert_eq!(GREASE_CIPHER_SUITES[0], 0x0A0A);
        assert_eq!(GREASE_CIPHER_SUITES[1], 0x1A1A);
        assert_eq!(GREASE_CIPHER_SUITES[2], 0x2A2A);
    }

    #[test]
    fn test_grease_tester_creation() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = GreaseTester::new(target);
        assert_eq!(tester.target.hostname, "example.com");
    }

    #[test]
    fn test_generate_recommendations_variants() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let ok_result = GreaseResult {
            tolerates_grease: true,
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec![],
            details: vec![],
            tests_performed: vec![],
        };
        let ok_recs = tester.generate_recommendations(&ok_result);
        assert!(ok_recs.iter().any(|r| r.contains("RFC 8701")));

        let bad_result = GreaseResult {
            tolerates_grease: false,
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec!["issue".to_string()],
            details: vec![],
            tests_performed: vec![],
        };
        let bad_recs = tester.generate_recommendations(&bad_result);
        assert!(bad_recs.iter().any(|r| r.contains("handle GREASE values")));
        assert!(
            bad_recs
                .iter()
                .any(|r| r.contains("Address the identified issues"))
        );
    }

    #[test]
    fn test_grease_result() {
        let result = GreaseResult {
            tolerates_grease: true,
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec![],
            details: vec!["Test".to_string()],
            tests_performed: vec!["GREASE cipher suites".to_string()],
        };

        assert!(result.tolerates_grease);
        assert_eq!(result.details.len(), 1);
        assert_eq!(result.tests_performed.len(), 1);
    }

    #[test]
    fn test_grease_report_fields() {
        let report = GreaseReport {
            grease_result: GreaseResult {
                tolerates_grease: false,
                inconclusive: true,
                direct_grease_test_performed: false,
                issues: vec!["issue".to_string()],
                details: vec!["detail".to_string()],
                tests_performed: vec![],
            },
            recommendations: vec!["rec".to_string()],
        };

        assert!(!report.grease_result.tolerates_grease);
        assert_eq!(report.grease_result.issues.len(), 1);
        assert_eq!(report.recommendations.len(), 1);
    }

    #[test]
    fn test_build_client_hello_with_grease_ciphers() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let hello = tester
            .build_client_hello_with_grease_ciphers()
            .expect("test assertion should succeed");

        // Check it's a valid TLS handshake record
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello

        // Check that GREASE values are present
        let has_grease = hello
            .windows(2)
            .any(|w| w == [0x0A, 0x0A] || w == [0x1A, 0x1A]);
        assert!(has_grease, "ClientHello should contain GREASE values");
    }

    #[test]
    fn test_build_client_hello_with_grease_extensions() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let hello = tester
            .build_client_hello_with_grease_extensions()
            .expect("test assertion should succeed");

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[5], 0x01);
        assert!(hello.len() > 100);
    }

    #[test]
    fn test_build_client_hello_with_grease_groups() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let hello = tester
            .build_client_hello_with_grease_groups()
            .expect("test assertion should succeed");

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn test_build_client_hello_combined_grease() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let hello = tester
            .build_client_hello_combined_grease()
            .expect("test assertion should succeed");

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[5], 0x01);
    }

    async fn spawn_dummy_server(max_accepts: usize) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((socket, _)) = listener.accept().await {
                    drop(socket);
                }
                remaining -= 1;
            }
        });
        addr
    }

    async fn spawn_self_signed_tls_server(max_accepts: usize) -> std::net::SocketAddr {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        acceptor.accept(stream),
                    )
                    .await;
                }
                remaining -= 1;
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_grease_baseline_ignores_certificate_validation_errors() {
        install_crypto_provider();
        let addr = spawn_self_signed_tls_server(1).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = GreaseTester::new(target);
        let baseline_ok = tester.test_baseline_connection().await.unwrap();
        assert!(baseline_ok);
    }

    #[tokio::test]
    async fn test_grease_tester_baseline_failure_path() {
        install_crypto_provider();
        let addr = spawn_dummy_server(5).await;
        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = GreaseTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.tolerates_grease);
        assert!(
            result.inconclusive,
            "baseline failure cannot be treated as a definitive GREASE result: {result:?}"
        );
        assert!(!result.direct_grease_test_performed);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.contains("Baseline connection failed"))
        );
    }

    #[test]
    fn test_grease_result_details_includes_issues() {
        let result = GreaseResult {
            tolerates_grease: false,
            inconclusive: true,
            direct_grease_test_performed: false,
            issues: vec!["Baseline connection failed".to_string()],
            details: vec!["Not tolerant".to_string()],
            tests_performed: vec![],
        };
        assert!(!result.tolerates_grease);
        assert!(result.details.iter().any(|d| d.contains("Not tolerant")));
        assert_eq!(result.issues.len(), 1);
    }

    #[test]
    fn test_recommendations_count_increases_with_issues() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let base_result = GreaseResult {
            tolerates_grease: false,
            inconclusive: true,
            direct_grease_test_performed: false,
            issues: Vec::new(),
            details: Vec::new(),
            tests_performed: Vec::new(),
        };
        let base_recs = tester.generate_recommendations(&base_result);

        let issue_result = GreaseResult {
            tolerates_grease: false,
            inconclusive: true,
            direct_grease_test_performed: false,
            issues: vec!["issue".to_string()],
            details: Vec::new(),
            tests_performed: Vec::new(),
        };
        let issue_recs = tester.generate_recommendations(&issue_result);

        assert!(issue_recs.len() > base_recs.len());
    }

    #[test]
    fn test_tolerates_grease_logic() {
        let mut result = GreaseResult {
            tolerates_grease: false, // Will be computed
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec![],
            details: vec!["✓ Server tolerates grease cipher suites".to_string()],
            tests_performed: vec!["test1".to_string()],
        };

        GreaseTester::finalize_grease_result(&mut result);
        assert!(result.tolerates_grease);
        assert!(!result.inconclusive);

        // When there are rejections, tolerates_grease should be false
        let mut result_with_rejection = GreaseResult {
            tolerates_grease: false,
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec!["Server rejected GREASE cipher suites (violates RFC 8701)".to_string()],
            details: vec![],
            tests_performed: vec!["test1".to_string()],
        };

        GreaseTester::finalize_grease_result(&mut result_with_rejection);
        assert!(!result_with_rejection.tolerates_grease);
        assert!(!result_with_rejection.inconclusive);
    }

    #[test]
    fn test_grease_partial_inconclusive_does_not_report_tolerant() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);
        let mut result = GreaseResult {
            tolerates_grease: false,
            inconclusive: false,
            direct_grease_test_performed: false,
            issues: vec![],
            details: vec!["✓ Baseline connection successful".to_string()],
            tests_performed: vec![],
        };

        tester.record_grease_test(
            &mut result,
            "GREASE cipher suites",
            Ok(GreaseTestOutcome::Tolerated),
        );
        tester.record_grease_test(
            &mut result,
            "GREASE extensions",
            Ok(GreaseTestOutcome::Inconclusive(
                "target closed connection".to_string(),
            )),
        );
        GreaseTester::finalize_grease_result(&mut result);

        assert!(!result.tolerates_grease);
        assert!(
            result.inconclusive,
            "partial GREASE evidence must stay inconclusive: {result:?}"
        );
    }

    #[test]
    fn test_grease_all_category_inconclusive_ignores_baseline_success_detail() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);
        let mut result = GreaseResult {
            tolerates_grease: false,
            inconclusive: false,
            direct_grease_test_performed: false,
            issues: vec![],
            details: vec!["✓ Baseline connection successful".to_string()],
            tests_performed: vec![],
        };

        tester.record_grease_test(
            &mut result,
            "GREASE supported groups",
            Ok(GreaseTestOutcome::Inconclusive(
                "no TLS response after ClientHello".to_string(),
            )),
        );
        GreaseTester::finalize_grease_result(&mut result);

        assert!(!result.tolerates_grease);
        assert!(
            result.inconclusive,
            "baseline success detail cannot make GREASE support definitive: {result:?}"
        );
    }
}
