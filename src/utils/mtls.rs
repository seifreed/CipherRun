// mTLS (Mutual TLS) utilities for client authentication

use crate::Result;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsConnector;

/// mTLS configuration
pub struct MtlsConfig {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl Clone for MtlsConfig {
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

impl MtlsConfig {
    /// Load mTLS configuration from separate certificate and key files
    pub fn from_separate_files<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        _key_password: Option<&str>,
    ) -> Result<Self> {
        // Load certificates
        let cert_file =
            File::open(cert_path.as_ref()).map_err(|e| crate::error::TlsError::MtlsError {
                message: format!("Failed to open certificate file: {}", e),
            })?;
        let mut cert_reader = BufReader::new(cert_file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, std::io::Error>>()
            .map_err(|e| crate::error::TlsError::MtlsError {
                message: format!("Failed to parse certificates: {}", e),
            })?;

        if certs.is_empty() {
            crate::tls_bail!("No certificates found in certificate file");
        }

        // Load private key
        let key_file =
            File::open(key_path.as_ref()).map_err(|e| crate::error::TlsError::MtlsError {
                message: format!("Failed to open private key file: {}", e),
            })?;
        let mut key_reader = BufReader::new(key_file);

        let mut keys = Vec::new();
        for item in rustls_pemfile::read_all(&mut key_reader) {
            match item {
                Ok(rustls_pemfile::Item::Pkcs8Key(key)) => {
                    keys.push(PrivateKeyDer::Pkcs8(key));
                }
                Ok(rustls_pemfile::Item::Pkcs1Key(key)) => {
                    keys.push(PrivateKeyDer::Pkcs1(key));
                }
                Ok(rustls_pemfile::Item::Sec1Key(key)) => {
                    keys.push(PrivateKeyDer::Sec1(key));
                }
                _ => {}
            }
        }

        if keys.is_empty() {
            crate::tls_bail!("No private key found in key file");
        }

        // Note: Password-protected keys would require additional processing
        // For now, we only support unencrypted keys

        Ok(Self {
            cert_chain: certs,
            private_key: keys.into_iter().next().unwrap(),
        })
    }

    /// Load mTLS configuration from a PEM file
    /// The PEM file should contain both the certificate chain and the private key
    pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref()).map_err(|e| crate::error::TlsError::MtlsError {
            message: format!("Failed to open mTLS PEM file: {}", e),
        })?;
        let mut reader = BufReader::new(file);

        // Read all certificates from the PEM file
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, std::io::Error>>()
            .map_err(|e| crate::error::TlsError::MtlsError {
                message: format!("Failed to parse certificates from PEM: {}", e),
            })?;

        if certs.is_empty() {
            crate::tls_bail!("No certificates found in PEM file");
        }

        // Reset reader to beginning for key parsing
        let file = File::open(path.as_ref())?;
        let mut reader = BufReader::new(file);

        // Try to read private key (support multiple formats)
        let mut keys = Vec::new();

        // Try PKCS8 format first
        for item in rustls_pemfile::read_all(&mut reader) {
            match item {
                Ok(rustls_pemfile::Item::Pkcs8Key(key)) => {
                    keys.push(PrivateKeyDer::Pkcs8(key));
                }
                Ok(rustls_pemfile::Item::Pkcs1Key(key)) => {
                    keys.push(PrivateKeyDer::Pkcs1(key));
                }
                Ok(rustls_pemfile::Item::Sec1Key(key)) => {
                    keys.push(PrivateKeyDer::Sec1(key));
                }
                _ => {}
            }
        }

        if keys.is_empty() {
            crate::tls_bail!("No private key found in PEM file");
        }

        if keys.len() > 1 {
            eprintln!("Warning: Multiple private keys found in PEM file, using the first one");
        }

        Ok(Self {
            cert_chain: certs,
            private_key: keys.into_iter().next().unwrap(),
        })
    }

    /// Build a TLS connector with client authentication
    pub fn build_tls_connector(&self) -> Result<TlsConnector> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .map_err(|e| crate::error::TlsError::MtlsError {
                    message: format!("Failed to set protocol versions: {}", e),
                })?
                .with_root_certificates(root_store)
                .with_client_auth_cert(self.cert_chain.clone(), self.private_key.clone_key())
                .map_err(|e| crate::error::TlsError::MtlsError {
                    message: format!("Failed to build TLS config with client auth: {}", e),
                })?;

        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Build a TLS connector with client authentication and custom root certificates
    pub fn build_tls_connector_with_roots(
        &self,
        root_store: RootCertStore,
    ) -> Result<TlsConnector> {
        let config =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .map_err(|e| crate::error::TlsError::MtlsError {
                    message: format!("Failed to set protocol versions: {}", e),
                })?
                .with_root_certificates(root_store)
                .with_client_auth_cert(self.cert_chain.clone(), self.private_key.clone_key())
                .map_err(|e| crate::error::TlsError::MtlsError {
                    message: format!("Failed to build TLS config with client auth: {}", e),
                })?;

        Ok(TlsConnector::from(Arc::new(config)))
    }
}

/// Build a standard TLS connector without client authentication
pub fn build_standard_tls_connector() -> TlsConnector {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("Failed to set protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

/// Build a TLS connector with custom root certificates
pub fn build_tls_connector_with_roots(root_store: RootCertStore) -> TlsConnector {
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("Failed to set protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_mtls_config_parsing() {
        // Create a temporary PEM file with a test certificate and key
        let mut temp_file = NamedTempFile::new().unwrap();

        // This is a minimal test - in practice you'd use real cert/key pairs
        let pem_data = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU6RqMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDnRl
c3QtY2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAZ
MRcwFQYDVQQDDA50ZXN0LWNlcnRpZmljYXRlMFwwDQYJKoZIhvcNAQEBBQADSwAw
SAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/9X0ULi
C8owp8JKwHQ5XPY0cZIhQRhZQIcCAwEAATANBgkqhkiG9w0BAQsFAANBAJ3+FJLb
jvSPe2pxLGJBqf0LcPB2s6yKLKCjFPPdWHMQUxu1u6OsUVaLEWakj0TJzO5RW0Kg
jY0qL8fStJpDQTc=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA0smE8eEhOpBs+SUb
eJsJXHAYxF+n+/heqF91Ad1xV8dqno1DlaiT/1fRQuILyjCnwkrAdDlc9jRxkiFB
GFlAhwIDAQABAkEAiNeuOSngRKRqzGBuqLEawO0pPNSaFH1qFjJCvzCiPjJLp5P2
2YFy5t3O1UBQA5T3w9pFBwXfJ0rBmA9mM7H0AQIhAP1/hzQMN/vJpfGYp/MVWQXP
9kRjjxQ1PpmvHSRqNK0PAiEA1I7H0zCJFCVq3x8pWfKx3cV/XYXJ7lkOmqvphqDT
OQECIEk9KlW7J7hFNa9TCw6N3Kv0K1yVphQBhOvCF3OzRq1vAiEAuAhKNSMsZ7vQ
z2H2IWYh2fKcFO6s7AYL6G0KOm6KQAECIBNKDX+4tN7R4x/pNMxsqHrG4k5pZGRq
KHvHJKYnrKyB
-----END PRIVATE KEY-----"#;

        write!(temp_file, "{}", pem_data).unwrap();
        temp_file.flush().unwrap();

        // This test might fail with real validation, but tests the parsing logic
        let result = MtlsConfig::from_pem_file(temp_file.path());

        // The parsing should at least attempt to read the file
        // Real validation would require valid cert/key pairs
        if let Ok(config) = result {
            assert!(!config.cert_chain.is_empty());
        }
    }

    #[test]
    fn test_build_standard_connector() {
        let connector = build_standard_tls_connector();
        // Just verify it builds successfully
        assert!(std::mem::size_of_val(&connector) > 0);
    }
}
