// Database Models Module
// Re-exports all database model types

pub mod certificate;
pub mod cipher;
pub mod protocol;
pub mod rating;
pub mod scan;
pub mod vulnerability;

pub use certificate::{CertificateRecord, ScanCertificateRecord};
pub use cipher::CipherRecord;
pub use protocol::ProtocolRecord;
pub use rating::RatingRecord;
pub use scan::ScanRecord;
pub use vulnerability::VulnerabilityRecord;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_model_reexports() {
        let scan = ScanRecord::new("example.com".to_string(), 443);
        assert_eq!(scan.target_hostname, "example.com");

        let rating = RatingRecord::new(1, "protocol".to_string(), 90);
        assert_eq!(rating.scan_id, 1);
        assert_eq!(rating.score, 90);
    }
}
