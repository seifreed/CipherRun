// Certificate Record Model
// Represents X.509 certificates with deduplication by fingerprint

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Certificate record in database (deduplicated by SHA256 fingerprint)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CertificateRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<i64>,
    pub fingerprint_sha256: String,  // Unique identifier
    pub subject: String,
    pub issuer: String,
    pub serial_number: Option<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature_algorithm: Option<String>,
    pub public_key_algorithm: Option<String>,
    pub public_key_size: Option<i32>,
    #[sqlx(default)]
    pub san_domains: Vec<String>,  // Array of SAN domains
    pub is_ca: bool,
    #[sqlx(default)]
    pub key_usage: Vec<String>,
    #[sqlx(default)]
    pub extended_key_usage: Vec<String>,
    pub der_bytes: Option<Vec<u8>>,  // Full DER encoding
    pub created_at: DateTime<Utc>,
}

/// Certificate chain junction table record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanCertificateRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub scan_id: i64,
    pub cert_id: i64,
    pub chain_position: i32,  // 0 = leaf, 1 = intermediate, etc.
}

impl CertificateRecord {
    /// Create new certificate record
    pub fn new(
        fingerprint_sha256: String,
        subject: String,
        issuer: String,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        is_ca: bool,
    ) -> Self {
        Self {
            cert_id: None,
            fingerprint_sha256,
            subject,
            issuer,
            serial_number: None,
            not_before,
            not_after,
            signature_algorithm: None,
            public_key_algorithm: None,
            public_key_size: None,
            san_domains: Vec::new(),
            is_ca,
            key_usage: Vec::new(),
            extended_key_usage: Vec::new(),
            der_bytes: None,
            created_at: Utc::now(),
        }
    }

    /// Set serial number
    pub fn with_serial(mut self, serial: String) -> Self {
        self.serial_number = Some(serial);
        self
    }

    /// Set algorithms
    pub fn with_algorithms(
        mut self,
        signature_algo: String,
        public_key_algo: String,
        key_size: usize,
    ) -> Self {
        self.signature_algorithm = Some(signature_algo);
        self.public_key_algorithm = Some(public_key_algo);
        self.public_key_size = Some(key_size as i32);
        self
    }

    /// Set SAN domains
    pub fn with_san_domains(mut self, domains: Vec<String>) -> Self {
        self.san_domains = domains;
        self
    }

    /// Set key usages
    pub fn with_key_usage(mut self, key_usage: Vec<String>, extended: Vec<String>) -> Self {
        self.key_usage = key_usage;
        self.extended_key_usage = extended;
        self
    }

    /// Set DER bytes
    pub fn with_der_bytes(mut self, der: Vec<u8>) -> Self {
        self.der_bytes = Some(der);
        self
    }
}

impl ScanCertificateRecord {
    /// Create new scan-certificate junction record
    pub fn new(scan_id: i64, cert_id: i64, chain_position: i32) -> Self {
        Self {
            id: None,
            scan_id,
            cert_id,
            chain_position,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_record_creation() {
        let now = Utc::now();
        let cert = CertificateRecord::new(
            "abc123".to_string(),
            "CN=example.com".to_string(),
            "CN=CA".to_string(),
            now,
            now,
            false,
        );

        assert_eq!(cert.fingerprint_sha256, "abc123");
        assert_eq!(cert.subject, "CN=example.com");
        assert!(!cert.is_ca);
    }

    #[test]
    fn test_scan_certificate_junction() {
        let junction = ScanCertificateRecord::new(1, 100, 0);
        assert_eq!(junction.scan_id, 1);
        assert_eq!(junction.cert_id, 100);
        assert_eq!(junction.chain_position, 0);
    }
}
