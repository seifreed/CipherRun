// Cipher Tester - Tests which cipher suites are supported by the server

use super::{CipherStrength, CipherSuite};
use crate::Result;
use crate::data::CIPHER_DB;
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use crate::utils::network::Target;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use serde::{Deserialize, Serialize};

/// Result of cipher testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherTestResult {
    pub cipher: CipherSuite,
    pub supported: bool,
    pub protocol: Protocol,
    pub server_preference: Option<usize>, // Position in server's preference list
    pub handshake_time_ms: Option<u64>,
}

/// Cipher testing summary for a protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCipherSummary {
    pub protocol: Protocol,
    pub supported_ciphers: Vec<CipherSuite>,
    pub server_ordered: bool,
    pub server_preference: Vec<String>, // Ordered list of cipher hexcodes
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

/// Cipher testing configuration
pub struct CipherTester {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    test_all_ciphers: bool,
    sleep_duration: Option<Duration>,
    use_rdp: bool,
    starttls_protocol: Option<crate::starttls::StarttlsProtocol>,
}

impl CipherTester {
    /// Create new cipher tester
    pub fn new(target: Target) -> Self {
        // Auto-detect RDP based on port
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            test_all_ciphers: false,
            sleep_duration: None,
            use_rdp,
            starttls_protocol: None,
        }
    }

    /// Set connect timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set read timeout
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Enable testing all ciphers (slower but comprehensive)
    pub fn test_all(mut self, enable: bool) -> Self {
        self.test_all_ciphers = enable;
        self
    }

    /// Set sleep duration between connections
    pub fn with_sleep(mut self, duration: Duration) -> Self {
        self.sleep_duration = Some(duration);
        self
    }

    /// Enable or disable RDP mode
    pub fn with_rdp(mut self, enable: bool) -> Self {
        self.use_rdp = enable;
        self
    }

    /// Set STARTTLS protocol
    pub fn with_starttls(mut self, protocol: Option<crate::starttls::StarttlsProtocol>) -> Self {
        self.starttls_protocol = protocol;
        self
    }

    /// Test all cipher suites for a specific protocol
    pub async fn test_protocol_ciphers(&self, protocol: Protocol) -> Result<ProtocolCipherSummary> {
        let ciphers = if self.test_all_ciphers {
            CIPHER_DB.get_all_ciphers()
        } else {
            // Test common/recommended ciphers only for speed
            CIPHER_DB.get_recommended_ciphers()
        };

        let mut supported = Vec::new();
        let mut results = Vec::new();

        // Count compatible ciphers for this protocol
        let _compatible_count = ciphers
            .iter()
            .filter(|c| self.is_cipher_compatible_with_protocol(c, protocol))
            .count();

        // Test each cipher
        for cipher in ciphers {
            if self.is_cipher_compatible_with_protocol(&cipher, protocol) {
                let result = self.test_single_cipher(&cipher, protocol).await?;
                if result.supported {
                    supported.push(cipher.clone());
                }
                results.push(result);

                // Sleep between requests if configured
                if let Some(sleep_dur) = self.sleep_duration {
                    tokio::time::sleep(sleep_dur).await;
                }
            }
        }

        // Determine server cipher preference order
        let server_preference = self
            .determine_server_preference(protocol, &supported)
            .await?;
        let server_ordered = !server_preference.is_empty();

        // Get preferred cipher (first in server's preference list)
        let preferred_cipher = if !server_preference.is_empty() {
            CIPHER_DB.get_by_hexcode(&server_preference[0])
        } else {
            supported.first().cloned()
        };

        // Calculate statistics
        let counts = self.calculate_cipher_counts(&supported);

        // Calculate average handshake time
        let handshake_times: Vec<u64> =
            results.iter().filter_map(|r| r.handshake_time_ms).collect();
        let avg_handshake_time_ms = if !handshake_times.is_empty() {
            Some(handshake_times.iter().sum::<u64>() / handshake_times.len() as u64)
        } else {
            None
        };

        Ok(ProtocolCipherSummary {
            protocol,
            supported_ciphers: supported,
            server_ordered,
            server_preference,
            preferred_cipher,
            counts,
            avg_handshake_time_ms,
        })
    }

    /// Test a single cipher suite
    pub async fn test_single_cipher(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
    ) -> Result<CipherTestResult> {
        // Parse hexcode - skip if it doesn't fit in u16
        let hexcode = match u16::from_str_radix(&cipher.hexcode, 16) {
            Ok(h) => h,
            Err(_) => {
                // Hexcode too large for u16, mark as unsupported
                return Ok(CipherTestResult {
                    cipher: cipher.clone(),
                    supported: false,
                    protocol,
                    server_preference: None,
                    handshake_time_ms: None,
                });
            }
        };

        let start = std::time::Instant::now();
        let supported = self.try_cipher_handshake(protocol, hexcode).await?;
        let handshake_time_ms = if supported {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        Ok(CipherTestResult {
            cipher: cipher.clone(),
            supported,
            protocol,
            server_preference: None, // Will be determined later
            handshake_time_ms,
        })
    }

    /// Attempt TLS handshake with specific cipher
    async fn try_cipher_handshake(&self, protocol: Protocol, cipher_hexcode: u16) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        // Connect TCP
        let mut stream = match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        // Send RDP preamble if needed
        if self.use_rdp
            && let Err(_) = crate::protocols::rdp::RdpPreamble::send(&mut stream).await
        {
            return Ok(false);
        }

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(false);
            }
        }

        // Build ClientHello with only this cipher
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_cipher(cipher_hexcode);

        // Add SNI and basic extensions
        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send ClientHello and read response
        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            // Read ServerHello or Alert
            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await?;

            if n == 0 {
                return Ok(false);
            }

            // Check if we got ServerHello (0x16 = Handshake, 0x02 = ServerHello)
            if n >= 6 && response[0] == 0x16 {
                // Look for ServerHello message
                if n > 5 && response[5] == 0x02 {
                    return Ok(true);
                }
            }

            // Check for Alert (0x15)
            if response[0] == 0x15 {
                return Ok(false);
            }

            Ok(false)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(false), // Timeout
        }
    }

    /// Determine server's cipher preference order
    async fn determine_server_preference(
        &self,
        protocol: Protocol,
        supported_ciphers: &[CipherSuite],
    ) -> Result<Vec<String>> {
        if supported_ciphers.is_empty() {
            return Ok(Vec::new());
        }

        let mut preference_order = Vec::new();

        // Send ClientHello with all supported ciphers in different orders
        // and see if server always picks the same one (server preference)
        // or picks our first one (client preference)

        let cipher_hexcodes: Vec<u16> = supported_ciphers
            .iter()
            .filter_map(|c| u16::from_str_radix(&c.hexcode, 16).ok())
            .collect();

        if cipher_hexcodes.len() < 2 {
            // Not enough ciphers to determine preference
            return Ok(supported_ciphers
                .iter()
                .map(|c| c.hexcode.clone())
                .collect());
        }

        // Test 1: Send ciphers in original order
        let first_choice = self
            .get_server_chosen_cipher(protocol, &cipher_hexcodes)
            .await?;

        tracing::debug!(
            "Cipher preference test 1 (original order): {:04x?}",
            first_choice
        );

        // Test 2: Send ciphers in reverse order
        let mut reversed = cipher_hexcodes.clone();
        reversed.reverse();
        let second_choice = self.get_server_chosen_cipher(protocol, &reversed).await?;

        tracing::debug!(
            "Cipher preference test 2 (reversed order): {:04x?}",
            second_choice
        );

        if first_choice == second_choice {
            // Server has preference (always picks the same cipher)
            tracing::debug!("Server has cipher preference (chose same cipher both times)");
            if let Some(chosen) = first_choice {
                preference_order.push(format!("{:04x}", chosen));

                // Find remaining ciphers in preference order
                for cipher in supported_ciphers {
                    let hex = cipher.hexcode.clone();
                    if !preference_order.contains(&hex) {
                        preference_order.push(hex);
                    }
                }
            }
        } else {
            // Client preference (server picks our first offered cipher)
            tracing::debug!("Client has cipher preference (server chose different ciphers)");
            // Return empty to indicate client preference
            return Ok(Vec::new());
        }

        Ok(preference_order)
    }

    /// Get the cipher that the server chooses from a list
    async fn get_server_chosen_cipher(
        &self,
        protocol: Protocol,
        cipher_hexcodes: &[u16],
    ) -> Result<Option<u16>> {
        let addr = self.target.socket_addrs()[0];

        let mut stream = match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(None);
            }
        }

        // Build ClientHello with all these ciphers
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(cipher_hexcodes);
        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send and read ServerHello
        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await?;

            if n >= 44 && response[0] == 0x16 && response[5] == 0x02 {
                // Parse chosen cipher from ServerHello
                // ServerHello structure:
                // 5 bytes: Record header
                // 4 bytes: Handshake header
                // 2 bytes: Server version
                // 32 bytes: Random
                // 1 byte: Session ID length
                // N bytes: Session ID
                // 2 bytes: Cipher suite <-- what we want

                let session_id_len = response[43] as usize;
                let cipher_offset = 44 + session_id_len;

                tracing::debug!(
                    "ServerHello: session_id_len={}, cipher_offset={}, response_len={}",
                    session_id_len,
                    cipher_offset,
                    n
                );

                if n >= cipher_offset + 2 {
                    let cipher =
                        u16::from_be_bytes([response[cipher_offset], response[cipher_offset + 1]]);
                    tracing::debug!("Server chose cipher: 0x{:04x}", cipher);
                    return Ok(Some(cipher));
                }
            }

            Ok(None)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(None),
        }
    }

    /// Check if cipher is compatible with protocol
    fn is_cipher_compatible_with_protocol(&self, cipher: &CipherSuite, protocol: Protocol) -> bool {
        // TLS 1.3 has its own cipher suites
        if matches!(protocol, Protocol::TLS13) {
            return cipher.protocol.contains("TLS13") || cipher.protocol.contains("TLSv1.3");
        }

        // SSLv2 has specific cipher format
        if matches!(protocol, Protocol::SSLv2) {
            return cipher.protocol.contains("SSLv2");
        }

        // SSLv3/TLS 1.0-1.2 share most ciphers
        // Exclude TLS 1.3 specific ciphers
        !cipher.protocol.contains("TLS13") && !cipher.protocol.contains("SSLv2")
    }

    /// Calculate cipher statistics
    fn calculate_cipher_counts(&self, ciphers: &[CipherSuite]) -> CipherCounts {
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

    /// Test all protocols and their ciphers
    pub async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>> {
        let mut results = HashMap::new();

        for protocol in Protocol::all() {
            // Skip QUIC for now
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

    /// Quick test - only test for cipher suite support, not order
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_cipher_detection() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = CipherTester::new(target);

        let summary = tester.test_protocol_ciphers(Protocol::TLS12).await.unwrap();

        // Should support at least some ciphers
        assert!(!summary.supported_ciphers.is_empty());

        // Should have forward secrecy ciphers
        assert!(summary.counts.forward_secrecy > 0);

        // Should not support NULL or EXPORT ciphers
        assert_eq!(summary.counts.null_ciphers, 0);
        assert_eq!(summary.counts.export_ciphers, 0);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_server_preference() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = CipherTester::new(target);

        let summary = tester.test_protocol_ciphers(Protocol::TLS12).await.unwrap();

        // Google should have server cipher preference
        assert!(summary.server_ordered);
        assert!(!summary.server_preference.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_quick_scan() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = CipherTester::new(target);

        let ciphers = tester.quick_test(Protocol::TLS12).await.unwrap();

        assert!(!ciphers.is_empty());
    }

    #[test]
    fn test_cipher_strength_calculation() {
        let cipher = CipherSuite {
            hexcode: "c030".to_string(),
            openssl_name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            iana_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES256-GCM".to_string(),
            mac: "SHA384".to_string(),
            bits: 256,
            export: false,
        };

        assert_eq!(cipher.strength(), CipherStrength::High);
        assert!(cipher.has_forward_secrecy());
        assert!(cipher.is_aead());
    }
}
