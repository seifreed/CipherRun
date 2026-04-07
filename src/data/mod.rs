// Data module - Data file parsing and management

pub mod ca_stores;
pub mod cipher_mapping;
pub mod client_data;
pub mod curves;

// Re-export commonly used types, statics, and accessor functions
pub use ca_stores::{CA_STORES, CACertificate, CAStore, CAStores, ca_stores};
pub use cipher_mapping::{CIPHER_DB, CipherDatabase, cipher_db};
pub use client_data::{CLIENT_DB, ClientDatabase, ClientProfile, client_db};
pub use curves::{CURVES_DB, CurvesDatabase, EllipticCurve, curves_db};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_store_construction() {
        let cert = CACertificate {
            subject: "CN=Example".to_string(),
            issuer: "CN=Issuer".to_string(),
            serial: "01".to_string(),
            not_after: "2030-01-01".to_string(),
            not_before: "2024-01-01".to_string(),
            der: vec![0x01, 0x02],
        };

        let store = CAStore {
            name: "Test Store".to_string(),
            certificates: vec![cert.clone()],
        };

        assert_eq!(store.name, "Test Store");
        assert_eq!(store.certificates.len(), 1);
        assert_eq!(store.certificates[0].serial, "01");
        assert_eq!(store.certificates[0].der, vec![0x01, 0x02]);
    }

    #[test]
    fn test_reexports_available() {
        // Test that accessor functions work
        let _ = cipher_db();
        let _ = curves_db();
        let _ = client_db();
        let _ = ca_stores();
    }

    #[test]
    fn test_empty_ca_store() {
        let store = CAStore {
            name: "Empty".to_string(),
            certificates: Vec::new(),
        };

        assert_eq!(store.name, "Empty");
        assert!(store.certificates.is_empty());
    }
}
