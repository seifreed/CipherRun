// CA Stores Loader - Loads PEM certificate stores

use anyhow::Result;
use std::sync::Arc;
use x509_parser::prelude::*;

/// Global CA stores loaded at startup
///
/// Uses OnceLock for safe initialization with proper error handling.
static CA_STORES_INNER: std::sync::OnceLock<Arc<CAStores>> = std::sync::OnceLock::new();

/// Get the global CA stores
///
/// Returns the stores if already initialized, or initializes it on first call.
/// Initialization errors are logged and an empty store is used as fallback.
pub fn ca_stores() -> Arc<CAStores> {
    CA_STORES_INNER
        .get_or_init(|| match CAStores::load() {
            Ok(stores) => Arc::new(stores),
            Err(e) => {
                tracing::error!("Failed to load CA stores: {}. Using empty stores.", e);
                Arc::new(CAStores::empty())
            }
        })
        .clone()
}

/// Legacy static for backward compatibility
/// Delegates to `ca_stores()` to avoid loading data twice into memory
pub static CA_STORES: std::sync::LazyLock<Arc<CAStores>> = std::sync::LazyLock::new(ca_stores);

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
    pub android: CAStore,
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
            android: CAStore::from_pem("Android", include_str!("../../data/Android.pem"))?,
            linux: CAStore::from_pem("Linux", include_str!("../../data/Linux.pem"))?,
            microsoft: CAStore::from_pem("Microsoft", include_str!("../../data/Microsoft.pem"))?,
            java: CAStore::from_pem("Java", include_str!("../../data/Java.pem"))?,
        })
    }

    /// Create empty stores (fallback for loading errors)
    pub fn empty() -> Self {
        Self {
            mozilla: CAStore {
                name: "Mozilla".to_string(),
                certificates: Vec::new(),
            },
            apple: CAStore {
                name: "Apple".to_string(),
                certificates: Vec::new(),
            },
            android: CAStore {
                name: "Android".to_string(),
                certificates: Vec::new(),
            },
            linux: CAStore {
                name: "Linux".to_string(),
                certificates: Vec::new(),
            },
            microsoft: CAStore {
                name: "Microsoft".to_string(),
                certificates: Vec::new(),
            },
            java: CAStore {
                name: "Java".to_string(),
                certificates: Vec::new(),
            },
        }
    }

    /// Get all stores as a slice
    pub fn all_stores(&self) -> Vec<&CAStore> {
        vec![
            &self.mozilla,
            &self.apple,
            &self.android,
            &self.linux,
            &self.microsoft,
            &self.java,
        ]
    }

    /// Get store by name
    pub fn get_store(&self, name: &str) -> Option<&CAStore> {
        match name.to_lowercase().as_str() {
            "mozilla" | "firefox" | "nss" => Some(&self.mozilla),
            "apple" | "macos" | "ios" => Some(&self.apple),
            "android" => Some(&self.android),
            "linux" => Some(&self.linux),
            "microsoft" | "windows" => Some(&self.microsoft),
            "java" | "jdk" => Some(&self.java),
            _ => None,
        }
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
        assert!(!stores.android.certificates.is_empty());
        assert!(!stores.linux.certificates.is_empty());
        assert!(!stores.microsoft.certificates.is_empty());
        assert!(!stores.java.certificates.is_empty());

        assert!(stores.total_certificates() > 100);
    }

    #[test]
    fn test_get_store_by_name() {
        let stores = CA_STORES.as_ref();

        assert!(stores.get_store("mozilla").is_some());
        assert!(stores.get_store("apple").is_some());
        assert!(stores.get_store("android").is_some());
        assert!(stores.get_store("windows").is_some());
        assert!(stores.get_store("java").is_some());
        assert!(stores.get_store("unknown").is_none());
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

    #[test]
    fn test_get_store_by_name_aliases() {
        let stores = CA_STORES.as_ref();
        assert!(stores.get_store("microsoft").is_some());
        assert!(stores.get_store("jdk").is_some());
    }

    #[test]
    fn test_all_stores_and_total_count() {
        let stores = CA_STORES.as_ref();
        let all = stores.all_stores();
        assert_eq!(all.len(), 6);

        let summed: usize = all.iter().map(|store| store.certificates.len()).sum();
        assert_eq!(stores.total_certificates(), summed);
    }
}
