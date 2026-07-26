use serde::{Deserialize, Serialize};

use crate::ciphers::CipherSuite;
use crate::protocols::Protocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherTestResult {
    pub cipher: CipherSuite,
    pub supported: bool,
    pub protocol: Protocol,
    pub server_preference: Option<usize>,
    pub handshake_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCipherSummary {
    pub protocol: Protocol,
    pub supported_ciphers: Vec<CipherSuite>,
    pub server_ordered: bool,
    pub server_preference: Vec<String>,
    pub preferred_cipher: Option<CipherSuite>,
    pub counts: CipherCounts,
    pub avg_handshake_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherCounts {
    pub total: usize,
    pub null_ciphers: usize,
    pub export_ciphers: usize,
    pub low_strength: usize,
    pub medium_strength: usize,
    pub high_strength: usize,
    pub forward_secrecy: usize,
    pub aead: usize,
}
