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
        if self.encryption.contains("NULL") {
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
        // TLS 1.3 always provides Forward Secrecy by design (RFC 8446)
        // All TLS 1.3 cipher suites use ephemeral key exchange (ECDHE or DHE)
        if self.protocol.contains("TLSv1.3") || self.protocol.contains("TLS13") {
            return true;
        }

        // For TLS 1.2 and earlier, check for ephemeral key exchange
        self.key_exchange.contains("ECDHE")
            || self.key_exchange.contains("DHE")
            || self.openssl_name.contains("ECDHE")
            || self.openssl_name.contains("DHE")
            || self.iana_name.contains("ECDHE")
            || self.iana_name.contains("DHE")
    }

    pub fn is_aead(&self) -> bool {
        self.encryption.contains("GCM")
            || self.encryption.contains("CCM")
            || self.encryption.contains("CHACHA20")
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
