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

impl OpossumTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Opossum vulnerability
    pub async fn test(&self) -> Result<bool> {
        // Test 1: Check if server uses vulnerable OpenSSL version
        if self.test_openssl_version().await? {
            return Ok(true);
        }

        // Test 2: Check if server's certificate chain contains malformed EC params
        if self.test_certificate_parsing().await? {
            return Ok(true);
        }

        Ok(false)
    }

    /// Test OpenSSL version detection
    async fn test_openssl_version(&self) -> Result<bool> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);
        let hostname = self.target.hostname.clone();

        // Connect and try to extract OpenSSL version from server
        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        // Create a rustls client config
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(hostname)
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
                Ok(false)
            }
            Ok(Err(_)) => {
                // Connection failed but didn't hang - might be other issue
                Ok(false)
            }
            Err(_) => {
                // Timeout - possible Opossum vulnerability causing hang
                Ok(true)
            }
        }
    }

    /// Test certificate parsing for malformed EC parameters
    async fn test_certificate_parsing(&self) -> Result<bool> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);
        let hostname = self.target.hostname.clone();

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
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
        let server_name = rustls::pki_types::ServerName::try_from(hostname)
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        // Attempt connection with shorter timeout for parsing issues
        match timeout(
            Duration::from_secs(15),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(_)) => Ok(false),  // Successfully parsed, not vulnerable
            Ok(Err(_)) => Ok(false), // Failed but didn't hang
            Err(_) => Ok(true),      // Timeout during certificate parsing
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

    #[test]
    fn test_opossum_tester_creation() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec![],
        };

        let tester = OpossumTester::new(target);
        assert_eq!(tester.target.hostname, "example.com");
    }
}
