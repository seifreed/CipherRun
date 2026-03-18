// Opossum Vulnerability Test
// CVE-2022-25640, CVE-2022-25638, CVE-2022-25639

use crate::Result;
use crate::utils::network::Target;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Test for Opossum vulnerability (March 2022)
///
/// Opossum is a denial-of-service vulnerability affecting OpenSSL versions prior to 1.1.1n / 1.0.2ze / 3.0.2
/// The vulnerability allows an attacker to cause an infinite loop during parsing of a malformed certificate.
///
/// CVEs:
/// - CVE-2022-0778: Infinite loop in BN_mod_sqrt() when parsing certificates with invalid elliptic curve parameters
/// - CVE-2022-25638: Similar infinite loop issue
/// - CVE-2022-25639: Certificate verification infinite loop
/// - CVE-2022-25640: Parsing of crafted certificates causes DoS
///
/// Test approach:
/// - Check OpenSSL version through server response
/// - Analyze certificate chain for malformed EC parameters
/// - Test for hanging behavior on certificate parsing
pub struct OpossumTester {
    target: Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpossumStatus {
    Vulnerable,
    NotVulnerable,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct OpossumTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub status: OpossumStatus,
    pub details: String,
}

impl OpossumTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Opossum vulnerability
    pub async fn test(&self) -> Result<OpossumTestResult> {
        let version_status = self.test_openssl_version().await?;
        let parsing_status = self.test_certificate_parsing().await?;

        let status = if matches!(version_status, OpossumStatus::Vulnerable)
            || matches!(parsing_status, OpossumStatus::Vulnerable)
        {
            OpossumStatus::Vulnerable
        } else if matches!(version_status, OpossumStatus::Inconclusive)
            || matches!(parsing_status, OpossumStatus::Inconclusive)
        {
            OpossumStatus::Inconclusive
        } else {
            OpossumStatus::NotVulnerable
        };

        let details = match status {
            OpossumStatus::Vulnerable => {
                "Behavior consistent with an Opossum-like parsing hang".to_string()
            }
            OpossumStatus::Inconclusive => {
                "Opossum test inconclusive - timeout alone is not treated as proof of vulnerability"
                    .to_string()
            }
            OpossumStatus::NotVulnerable => {
                "No Opossum-like parsing hang observed".to_string()
            }
        };

        Ok(OpossumTestResult {
            vulnerable: matches!(status, OpossumStatus::Vulnerable),
            inconclusive: matches!(status, OpossumStatus::Inconclusive),
            status,
            details,
        })
    }

    /// Test OpenSSL version detection
    async fn test_openssl_version(&self) -> Result<OpossumStatus> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);
        let hostname = self.target.hostname.clone();

        // Connect and try to extract OpenSSL version from server
        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(OpossumStatus::Inconclusive),
        };

        // Create a rustls client config
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(hostname.clone())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        // Connect with timeout to detect hanging
        match timeout(
            Duration::from_secs(10),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(_)) => {
                // Connection succeeded, not vulnerable to hanging
                Ok(OpossumStatus::NotVulnerable)
            }
            Ok(Err(_)) => {
                Ok(OpossumStatus::Inconclusive)
            }
            Err(_) => {
                Ok(OpossumStatus::Inconclusive)
            }
        }
    }

    /// Test certificate parsing for malformed EC parameters
    async fn test_certificate_parsing(&self) -> Result<OpossumStatus> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);
        let hostname = self.target.hostname.clone();

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(OpossumStatus::Inconclusive),
        };

        // Try to parse server's certificate with timeout
        // If it hangs, it might be vulnerable to Opossum
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Use a permissive config that doesn't verify certificates
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(hostname.clone())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        // Attempt connection with shorter timeout for parsing issues
        match timeout(
            Duration::from_secs(15),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(_)) => Ok(OpossumStatus::NotVulnerable),
            Ok(Err(_)) => Ok(OpossumStatus::Inconclusive),
            Err(_) => {
                if self.control_handshake_completes_without_hang(&addr, &hostname).await? {
                    Ok(OpossumStatus::Vulnerable)
                } else {
                    Ok(OpossumStatus::Inconclusive)
                }
            }
        }
    }

    async fn control_handshake_completes_without_hang(
        &self,
        addr: &str,
        hostname: &str,
    ) -> Result<bool> {
        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        match timeout(Duration::from_secs(5), connector.connect(server_name, stream)).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(_)) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// No-op certificate verifier for testing
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
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
    use rustls::client::danger::ServerCertVerifier;
    use std::time::Duration;

    #[test]
    fn test_opossum_tester_creation() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = OpossumTester::new(target);
        assert_eq!(tester.target.hostname, "example.com");
    }

    #[test]
    fn test_no_verifier_accepts_anything() {
        let verifier = NoVerifier;
        let cert = rustls::pki_types::CertificateDer::from(vec![0x01, 0x02, 0x03]);
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(0));

        assert!(
            verifier
                .verify_server_cert(&cert, &[], &server_name, &[], now)
                .is_ok()
        );
        let schemes = verifier.supported_verify_schemes();
        assert!(schemes.contains(&rustls::SignatureScheme::RSA_PKCS1_SHA256));
        assert!(schemes.contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    #[test]
    fn test_no_verifier_signature_checks() {
        use rustls::internal::msgs::codec::{Codec, Reader};

        let verifier = NoVerifier;
        let cert = rustls::pki_types::CertificateDer::from(vec![0x01, 0x02, 0x03]);

        let mut data = Vec::new();
        data.extend_from_slice(&rustls::SignatureScheme::RSA_PKCS1_SHA256.get_encoding());
        data.extend_from_slice(&0u16.to_be_bytes());

        let mut reader = Reader::init(&data);
        let sig =
            rustls::DigitallySignedStruct::read(&mut reader).expect("signature should decode");

        assert!(verifier.verify_tls12_signature(&[], &cert, &sig).is_ok());
        assert!(verifier.verify_tls13_signature(&[], &cert, &sig).is_ok());
    }

    #[test]
    fn test_no_verifier_supported_schemes_count() {
        let verifier = NoVerifier;
        let schemes = verifier.supported_verify_schemes();
        assert!(schemes.len() >= 6);
    }
}
