// CA Stores Loader - Loads PEM certificate stores

use anyhow::Result;
use lazy_static::lazy_static;
use std::sync::Arc;
use x509_parser::prelude::*;

lazy_static! {
    /// Global CA stores loaded at startup
    pub static ref CA_STORES: Arc<CAStores> = Arc::new(
        CAStores::load().expect("Failed to load CA stores")
    );
}

/// A single CA certificate
#[derive(Debug, Clone)]
pub struct CACertificate {
    /// Subject
    pub subject: String,
    /// Issuer
    pub issuer: String,
    /// Serial number
    pub serial: String,
    /// Not before
    pub not_before: String,
    /// Not after
    pub not_after: String,
    /// Raw DER bytes
    pub der: Vec<u8>,
}

/// CA certificate store
#[derive(Debug)]
pub struct CAStore {
    pub name: String,
    pub certificates: Vec<CACertificate>,
}

impl CAStore {
    /// Load from PEM data
    fn from_pem(name: &str, data: &str) -> Result<Self> {
        let mut certificates = Vec::new();

        // Use x509-parser's built-in PEM parsing
        for pem_result in Pem::iter_from_buffer(data.as_bytes()) {
            match pem_result {
                Ok(pem) => {
                    if pem.label == "CERTIFICATE"
                        && let Ok((_, cert)) = X509Certificate::from_der(&pem.contents)
                    {
                        let ca_cert = CACertificate {
                            subject: cert.subject().to_string(),
                            issuer: cert.issuer().to_string(),
                            serial: format!("{:x}", cert.serial),
                            not_before: cert.validity().not_before.to_string(),
                            not_after: cert.validity().not_after.to_string(),
                            der: pem.contents.to_vec(),
                        };
                        certificates.push(ca_cert);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to parse PEM certificate in {}: {:?}",
                        name, e
                    );
                }
            }
        }

        Ok(Self {
            name: name.to_string(),
            certificates,
        })
    }
}

/// All CA stores
pub struct CAStores {
    pub mozilla: CAStore,
    pub apple: CAStore,
    pub linux: CAStore,
    pub microsoft: CAStore,
    pub java: CAStore,
}

impl CAStores {
    /// Load all CA stores from embedded data
    pub fn load() -> Result<Self> {
        Ok(Self {
            mozilla: CAStore::from_pem("Mozilla", include_str!("../../data/Mozilla.pem"))?,
            apple: CAStore::from_pem("Apple", include_str!("../../data/Apple.pem"))?,
            linux: CAStore::from_pem("Linux", include_str!("../../data/Linux.pem"))?,
            microsoft: CAStore::from_pem("Microsoft", include_str!("../../data/Microsoft.pem"))?,
            java: CAStore::from_pem("Java", include_str!("../../data/Java.pem"))?,
        })
    }

    /// Get all stores as a slice
    pub fn all_stores(&self) -> Vec<&CAStore> {
        vec![
            &self.mozilla,
            &self.apple,
            &self.linux,
            &self.microsoft,
            &self.java,
        ]
    }

    /// Total certificate count across all stores
    pub fn total_certificates(&self) -> usize {
        self.all_stores().iter().map(|s| s.certificates.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_ca_stores() {
        let stores = CA_STORES.as_ref();

        assert!(!stores.mozilla.certificates.is_empty());
        assert!(!stores.apple.certificates.is_empty());
        assert!(!stores.linux.certificates.is_empty());
        assert!(!stores.microsoft.certificates.is_empty());
        assert!(!stores.java.certificates.is_empty());

        assert!(stores.total_certificates() > 100);
    }

    #[test]
    fn test_ca_certificate_fields() {
        let stores = CA_STORES.as_ref();

        if let Some(cert) = stores.mozilla.certificates.first() {
            assert!(!cert.subject.is_empty());
            assert!(!cert.issuer.is_empty());
            assert!(!cert.serial.is_empty());
            assert!(!cert.der.is_empty());
        }
    }
}
