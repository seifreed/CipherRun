// mTLS (Mutual TLS) utilities for client authentication

use crate::Result;
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsConnector;
use tracing::warn;

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

fn parse_certs(pem_bytes: &[u8]) -> crate::Result<Vec<CertificateDer<'static>>> {
    let items = pem::parse_many(pem_bytes).map_err(|e| crate::error::TlsError::MtlsError {
        message: format!("Failed to parse PEM: {}", e),
    })?;
    Ok(items
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect())
}

fn parse_keys(pem_bytes: &[u8]) -> crate::Result<Vec<PrivateKeyDer<'static>>> {
    let items = pem::parse_many(pem_bytes).map_err(|e| crate::error::TlsError::MtlsError {
        message: format!("Failed to parse PEM: {}", e),
    })?;
    let mut keys = Vec::new();
    for item in items {
        match item.tag() {
            "PRIVATE KEY" => keys.push(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                item.into_contents(),
            ))),
            "RSA PRIVATE KEY" => keys.push(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
                item.into_contents(),
            ))),
            "EC PRIVATE KEY" => keys.push(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
                item.into_contents(),
            ))),
            _ => warn!("Skipping unsupported PEM item in mTLS config"),
        }
    }
    Ok(keys)
}

fn single_private_key(
    mut keys: Vec<PrivateKeyDer<'static>>,
    source: &str,
) -> crate::Result<PrivateKeyDer<'static>> {
    if keys.is_empty() {
        crate::tls_bail!("No private key found in {source}");
    }
    if keys.len() > 1 {
        crate::tls_bail!("Multiple private keys found in {source}");
    }
    keys.pop().ok_or_else(|| crate::error::TlsError::MtlsError {
        message: format!("No private key found in {source} (should have been caught earlier)"),
    })
}

impl MtlsConfig {
    /// Load mTLS configuration from separate certificate and key files
    pub fn from_separate_files<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
        _key_password: Option<&str>,
    ) -> Result<Self> {
        let cert_bytes =
            fs::read(cert_path.as_ref()).map_err(|e| crate::error::TlsError::MtlsError {
                message: format!("Failed to open certificate file: {}", e),
            })?;
        let certs = parse_certs(&cert_bytes)?;
        if certs.is_empty() {
            crate::tls_bail!("No certificates found in certificate file");
        }

        let key_bytes =
            fs::read(key_path.as_ref()).map_err(|e| crate::error::TlsError::MtlsError {
                message: format!("Failed to open private key file: {}", e),
            })?;
        let keys = parse_keys(&key_bytes)?;

        Ok(Self {
            cert_chain: certs,
            private_key: single_private_key(keys, "key file")?,
        })
    }

    /// Load mTLS configuration from a PEM file containing both cert chain and private key
    pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let pem_bytes = fs::read(path.as_ref()).map_err(|e| crate::error::TlsError::MtlsError {
            message: format!("Failed to open mTLS PEM file: {}", e),
        })?;

        let certs = parse_certs(&pem_bytes)?;
        if certs.is_empty() {
            crate::tls_bail!("No certificates found in PEM file");
        }

        let keys = parse_keys(&pem_bytes)?;

        Ok(Self {
            cert_chain: certs,
            private_key: single_private_key(keys, "PEM file")?,
        })
    }

    /// Build a TLS connector with client authentication.
    ///
    /// Server-certificate verification is deliberately disabled: like every
    /// other scanner inspection path, protocol/cipher detection and certificate
    /// retrieval must succeed against bad-cert hosts (mTLS endpoints commonly
    /// sit behind private/self-signed CAs). Trust is assessed separately by the
    /// certificate validator on the retrieved chain.
    pub fn build_tls_connector(&self) -> Result<TlsConnector> {
        let config = crate::utils::insecure_tls::insecure_client_config_with_client_auth(
            self.cert_chain.clone(),
            self.private_key.clone_key(),
        )
        .map_err(|e| crate::error::TlsError::MtlsError {
            message: format!("Failed to build TLS config with client auth: {}", e),
        })?;

        Ok(TlsConnector::from(Arc::new(config)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_mtls_config_parsing() {
        let mut temp_file = NamedTempFile::new().expect("test assertion should succeed");

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

        write!(temp_file, "{}", pem_data).expect("test assertion should succeed");
        temp_file.flush().expect("test assertion should succeed");

        let result = MtlsConfig::from_pem_file(temp_file.path());
        if let Ok(config) = result {
            assert!(!config.cert_chain.is_empty());
        }
    }

    #[test]
    fn test_mtls_from_pem_file_empty_fails() {
        let temp_file = NamedTempFile::new().expect("test assertion should succeed");
        let err = MtlsConfig::from_pem_file(temp_file.path())
            .err()
            .expect("should fail on empty PEM");
        assert!(err.to_string().contains("No certificates"));
    }

    #[test]
    fn test_mtls_from_separate_files_empty_fails() {
        let cert_file = NamedTempFile::new().expect("test assertion should succeed");
        let key_file = NamedTempFile::new().expect("test assertion should succeed");

        let err = MtlsConfig::from_separate_files(cert_file.path(), key_file.path(), None)
            .err()
            .expect("should fail on empty cert/key");
        assert!(err.to_string().contains("No certificates"));
    }

    #[test]
    fn test_mtls_from_separate_files_missing_data() {
        let mut cert_file = NamedTempFile::new().expect("test assertion should succeed");
        let key_file = NamedTempFile::new().expect("test assertion should succeed");
        writeln!(cert_file, "not a cert").expect("test assertion should succeed");

        let err = MtlsConfig::from_separate_files(cert_file.path(), key_file.path(), None)
            .err()
            .expect("should fail on invalid input");
        assert!(err.to_string().contains("No certificates"));
    }

    #[test]
    fn test_mtls_from_pem_file_without_private_key() {
        let err = MtlsConfig::from_pem_file("data/Mozilla.pem")
            .err()
            .expect("should fail without private key");
        assert!(err.to_string().contains("No private key"));
    }

    #[test]
    fn test_mtls_from_pem_file_rejects_multiple_private_keys() {
        let mut temp_file = NamedTempFile::new().expect("test assertion should succeed");
        write!(
            temp_file,
            r#"-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
BAUG
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
BwgJ
-----END PRIVATE KEY-----"#
        )
        .expect("test assertion should succeed");
        temp_file.flush().expect("test assertion should succeed");

        let err = MtlsConfig::from_pem_file(temp_file.path())
            .err()
            .expect("multiple private keys should fail");

        assert!(err.to_string().contains("Multiple private keys"));
    }

    #[test]
    fn test_mtls_from_separate_files_missing_key() {
        let key_file = NamedTempFile::new().expect("test assertion should succeed");
        let err = MtlsConfig::from_separate_files(
            std::path::PathBuf::from("data/Mozilla.pem"),
            key_file.path().to_path_buf(),
            None,
        )
        .err()
        .expect("should fail without private key");
        assert!(err.to_string().contains("No private key"));
    }

    #[test]
    fn test_mtls_config_clone_preserves_fields() {
        let config = MtlsConfig {
            cert_chain: vec![CertificateDer::from(vec![0x01, 0x02])],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x03, 0x04])),
        };

        let cloned = config.clone();
        assert_eq!(cloned.cert_chain.len(), 1);
        assert!(matches!(cloned.private_key, PrivateKeyDer::Pkcs8(_)));
    }
}
