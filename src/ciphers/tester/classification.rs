use super::{CIPHER_DB, CipherCounts, CipherStrength, CipherSuite, CipherTester, Result};
use crate::protocols::Protocol;
use std::collections::HashMap;

impl CipherTester {
    pub(super) fn is_cipher_compatible_with_protocol(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
    ) -> bool {
        let cipher_protocol = cipher.protocol.to_ascii_uppercase();

        if matches!(protocol, Protocol::TLS13) {
            return cipher_protocol.contains("TLS13") || cipher_protocol.contains("TLSV1.3");
        }

        if matches!(protocol, Protocol::SSLv2) {
            return cipher_protocol.contains("SSLV2");
        }

        // For TLS 1.0/1.1, exclude ciphers defined only for TLS 1.2+.
        // AES-GCM and other TLS 1.2-only suites (RFC 5288/5289) are not valid
        // for older protocol versions — testing them wastes probes and can produce
        // false positives if a server mistakenly accepts them.
        if matches!(
            protocol,
            Protocol::TLS10 | Protocol::TLS11 | Protocol::SSLv3
        ) {
            // Exclude ciphers that are EXCLUSIVELY TLS 1.2+.
            // The cipher DB stores a single protocol value (e.g. "TLSv1.2"), never
            // comma-separated, so we check for TLS 1.2/TLS12 without the presence
            // of any older version string.
            let is_tls12_exclusive = (cipher_protocol.contains("TLSV1.2")
                || cipher_protocol.contains("TLS12"))
                && !cipher_protocol.contains("TLSV1.1")
                && !cipher_protocol.contains("TLSV1.0");
            return !cipher_protocol.contains("TLS13")
                && !cipher_protocol.contains("TLSV1.3")
                && !cipher_protocol.contains("SSLV2")
                && !is_tls12_exclusive;
        }

        // TLS 1.2: exclude TLS 1.3-only and SSLv2 ciphers.
        !cipher_protocol.contains("TLS13")
            && !cipher_protocol.contains("TLSV1.3")
            && !cipher_protocol.contains("SSLV2")
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
