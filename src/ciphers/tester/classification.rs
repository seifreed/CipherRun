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

        // For TLS 1.0/1.1/1.2, most ciphers are backward-compatible, so we test
        // them against older protocols too. Only exclude TLS 1.3-only and SSLv2 ciphers.
        // However, some TLS 1.2-specific ciphers (like AES-GCM suites) were never
        // defined for older protocols. We use explicit protocol matching here:
        // if a cipher's protocol string exactly matches a newer version and the
        // target protocol is older, we still test it (the handshake will simply
        // fail if the server doesn't support it).
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
