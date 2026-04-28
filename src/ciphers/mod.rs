// Ciphers module - Cipher suite definitions and testing

use serde::{Deserialize, Serialize};
use std::fmt;

/// Cipher suite information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuite {
    pub hexcode: String,
    pub openssl_name: String,
    pub iana_name: String,
    pub protocol: String,
    pub key_exchange: String,
    pub authentication: String,
    pub encryption: String,
    pub mac: String,
    pub bits: u16,
    pub export: bool,
}

/// Cipher strength category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherStrength {
    NULL,
    Export,
    Low,
    Medium,
    High,
}

impl CipherSuite {
    pub fn strength(&self) -> CipherStrength {
        let encryption = self.encryption.to_ascii_uppercase();
        if encryption.contains("NULL") {
            CipherStrength::NULL
        } else if self.export {
            CipherStrength::Export
        } else if self.bits < 128 {
            CipherStrength::Low
        } else if self.bits < 256 {
            CipherStrength::Medium
        } else {
            CipherStrength::High
        }
    }

    pub fn has_forward_secrecy(&self) -> bool {
        let protocol = self.protocol.to_ascii_uppercase();
        let key_exchange = self.key_exchange.to_ascii_uppercase();
        let openssl_name = self.openssl_name.to_ascii_uppercase();
        let iana_name = self.iana_name.to_ascii_uppercase();

        // TLS 1.3 always provides Forward Secrecy by design (RFC 8446)
        // All TLS 1.3 cipher suites use ephemeral key exchange (ECDHE or DHE)
        if protocol.contains("TLSV1.3") || protocol.contains("TLS13") {
            return true;
        }

        // For TLS 1.2 and earlier, check for ephemeral key exchange
        key_exchange.contains("ECDHE")
            || key_exchange.contains("DHE")
            || key_exchange.contains("EDH")
            || openssl_name.contains("ECDHE")
            || openssl_name.contains("DHE")
            || openssl_name.contains("EDH")
            || iana_name.contains("ECDHE")
            || iana_name.contains("DHE")
    }

    pub fn is_aead(&self) -> bool {
        let encryption = self.encryption.to_ascii_uppercase();
        encryption.contains("GCM") || encryption.contains("CCM") || encryption.contains("CHACHA20")
    }

    /// Quantum-safety is determined by the negotiated key exchange *group*, not the cipher suite.
    /// Classical ECDHE/DHE/RSA are all broken by Shor's algorithm regardless of cipher strength.
    /// Check `KeyExchangeGroup::quantum_vulnerable` for the actual negotiated group assessment.
    pub fn is_quantum_safe(&self) -> bool {
        false
    }
}

impl fmt::Display for CipherStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherStrength::NULL => write!(f, "NULL"),
            CipherStrength::Export => write!(f, "EXPORT"),
            CipherStrength::Low => write!(f, "LOW"),
            CipherStrength::Medium => write!(f, "MEDIUM"),
            CipherStrength::High => write!(f, "HIGH"),
        }
    }
}

pub mod parser;
pub mod tester;

pub use tester::{CipherTestable, CipherTester, ProtocolCipherSummary};

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cipher() -> CipherSuite {
        CipherSuite {
            hexcode: "0x1301".to_string(),
            openssl_name: "TLS_AES_128_GCM_SHA256".to_string(),
            iana_name: "TLS_AES_128_GCM_SHA256".to_string(),
            protocol: "TLSv1.3".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AESGCM".to_string(),
            mac: "AEAD".to_string(),
            bits: 128,
            export: false,
        }
    }

    #[test]
    fn test_cipher_strength_categories() {
        let mut cipher = base_cipher();
        cipher.encryption = "NULL".to_string();
        assert_eq!(cipher.strength(), CipherStrength::NULL);

        cipher.encryption = "RC4".to_string();
        cipher.export = true;
        assert_eq!(cipher.strength(), CipherStrength::Export);

        cipher.export = false;
        cipher.bits = 112;
        assert_eq!(cipher.strength(), CipherStrength::Low);

        cipher.bits = 128;
        assert_eq!(cipher.strength(), CipherStrength::Medium);

        cipher.bits = 256;
        assert_eq!(cipher.strength(), CipherStrength::High);
    }

    #[test]
    fn test_cipher_forward_secrecy_and_aead() {
        let cipher = base_cipher();
        assert!(cipher.has_forward_secrecy());
        assert!(cipher.is_aead());
    }

    #[test]
    fn test_cipher_helpers_without_forward_secrecy() {
        let mut cipher = base_cipher();
        cipher.protocol = "TLSv1.2".to_string();
        cipher.key_exchange = "RSA".to_string();
        cipher.openssl_name = "TLS_RSA_WITH_AES_128_CBC_SHA".to_string();
        cipher.iana_name = "TLS_RSA_WITH_AES_128_CBC_SHA".to_string();
        cipher.encryption = "AES-CBC".to_string();

        assert!(!cipher.has_forward_secrecy());
        assert!(!cipher.is_aead());
    }

    #[test]
    fn test_cipher_strength_display() {
        assert_eq!(format!("{}", CipherStrength::High), "HIGH");
    }

    #[test]
    fn test_cipher_is_aead_chacha20() {
        let mut cipher = base_cipher();
        cipher.encryption = "CHACHA20-POLY1305".to_string();
        assert!(cipher.is_aead());
    }

    #[test]
    fn test_cipher_helpers_are_case_insensitive() {
        let mut cipher = base_cipher();
        cipher.protocol = "tlsv1.3".to_string();
        cipher.key_exchange = "ecdhe".to_string();
        cipher.openssl_name = "tls_aes_128_gcm_sha256".to_string();
        cipher.iana_name = "tls_aes_128_gcm_sha256".to_string();
        cipher.encryption = "aesgcm".to_string();

        assert!(cipher.has_forward_secrecy());
        assert!(cipher.is_aead());

        cipher.encryption = "null".to_string();
        assert_eq!(cipher.strength(), CipherStrength::NULL);
    }
}
