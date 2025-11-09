// Cipher Suite Record Model
// Represents cipher suites detected during a scan

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Cipher suite record in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CipherRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_id: Option<i64>,
    pub scan_id: i64,
    pub protocol_name: String,  // "TLS 1.2", "TLS 1.3", etc.
    pub cipher_name: String,    // Full cipher suite name
    pub key_exchange: Option<String>,
    pub authentication: Option<String>,
    pub encryption: Option<String>,
    pub mac: Option<String>,
    pub bits: Option<i32>,
    pub forward_secrecy: bool,
    pub strength: String,  // "weak", "medium", "strong"
}

impl CipherRecord {
    /// Create new cipher record
    pub fn new(
        scan_id: i64,
        protocol_name: String,
        cipher_name: String,
        strength: String,
        forward_secrecy: bool,
    ) -> Self {
        Self {
            cipher_id: None,
            scan_id,
            protocol_name,
            cipher_name,
            key_exchange: None,
            authentication: None,
            encryption: None,
            mac: None,
            bits: None,
            forward_secrecy,
            strength,
        }
    }

    /// Set cipher details
    pub fn with_details(
        mut self,
        key_exchange: String,
        authentication: String,
        encryption: String,
        mac: String,
        bits: u16,
    ) -> Self {
        self.key_exchange = Some(key_exchange);
        self.authentication = Some(authentication);
        self.encryption = Some(encryption);
        self.mac = Some(mac);
        self.bits = Some(bits as i32);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_record_creation() {
        let cipher = CipherRecord::new(
            1,
            "TLS 1.3".to_string(),
            "TLS_AES_256_GCM_SHA384".to_string(),
            "strong".to_string(),
            true,
        );

        assert_eq!(cipher.scan_id, 1);
        assert_eq!(cipher.protocol_name, "TLS 1.3");
        assert!(cipher.forward_secrecy);
        assert_eq!(cipher.strength, "strong");
    }
}
