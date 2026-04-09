use super::{CIPHER_DB, CipherCounts, CipherStrength, CipherSuite, CipherTester, Result};
use crate::protocols::Protocol;
use std::collections::HashMap;

impl CipherTester {
    pub(super) fn is_cipher_compatible_with_protocol(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
    ) -> bool {
        if matches!(protocol, Protocol::TLS13) {
            return cipher.protocol.contains("TLS13") || cipher.protocol.contains("TLSv1.3");
        }

        if matches!(protocol, Protocol::SSLv2) {
            return cipher.protocol.contains("SSLv2");
        }

        !cipher.protocol.contains("TLS13")
            && !cipher.protocol.contains("TLSv1.3")
            && !cipher.protocol.contains("SSLv2")
    }

    pub(super) fn calculate_cipher_counts(&self, ciphers: &[CipherSuite]) -> CipherCounts {
        let mut counts = CipherCounts {
            total: ciphers.len(),
            ..Default::default()
        };

        for cipher in ciphers {
            match cipher.strength() {
                CipherStrength::NULL => counts.null_ciphers += 1,
                CipherStrength::Export => counts.export_ciphers += 1,
                CipherStrength::Low => counts.low_strength += 1,
                CipherStrength::Medium => counts.medium_strength += 1,
                CipherStrength::High => counts.high_strength += 1,
            }

            if cipher.has_forward_secrecy() {
                counts.forward_secrecy += 1;
            }

            if cipher.is_aead() {
                counts.aead += 1;
            }
        }

        counts
    }

    pub async fn test_all_protocols(
        &self,
    ) -> Result<HashMap<Protocol, super::ProtocolCipherSummary>> {
        let mut results = HashMap::new();
        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let summary = self.test_protocol_ciphers(protocol).await?;
            if !summary.supported_ciphers.is_empty() {
                results.insert(protocol, summary);
            }
        }
        Ok(results)
    }

    pub async fn quick_test(&self, protocol: Protocol) -> Result<Vec<CipherSuite>> {
        let common_ciphers = CIPHER_DB.get_recommended_ciphers();
        let mut supported = Vec::new();

        for cipher in common_ciphers {
            if self.is_cipher_compatible_with_protocol(&cipher, protocol) {
                let result = self.test_single_cipher(&cipher, protocol).await?;
                if result.supported {
                    supported.push(cipher);
                }
            }
        }

        Ok(supported)
    }
}
