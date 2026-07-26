use cipherrun::ciphers::CipherSuite;
use cipherrun::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
use cipherrun::protocols::Protocol;

pub fn build_cipher_summary(protocol: Protocol) -> ProtocolCipherSummary {
    let cipher = CipherSuite {
        hexcode: "1301".to_string(),
        openssl_name: "TLS_AES_128_GCM_SHA256".to_string(),
        iana_name: "TLS_AES_128_GCM_SHA256".to_string(),
        protocol: "TLSv1.3".to_string(),
        key_exchange: "ECDHE".to_string(),
        authentication: "AEAD".to_string(),
        encryption: "AES_128_GCM".to_string(),
        mac: "AEAD".to_string(),
        bits: 128,
        export: false,
    };

    ProtocolCipherSummary {
        protocol,
        supported_ciphers: vec![cipher],
        server_ordered: true,
        server_preference: vec!["1301".to_string()],
        preferred_cipher: None,
        counts: CipherCounts {
            total: 1,
            null_ciphers: 0,
            export_ciphers: 0,
            low_strength: 0,
            medium_strength: 1,
            high_strength: 0,
            forward_secrecy: 1,
            aead: 1,
        },
        avg_handshake_time_ms: Some(10),
    }
}
