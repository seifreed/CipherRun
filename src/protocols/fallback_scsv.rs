// TLS Fallback SCSV (Signaling Cipher Suite Value) Testing
// RFC 7507 - TLS_FALLBACK_SCSV prevents protocol downgrade attacks
// Protects against attacks like POODLE by preventing fallback to older protocols

use crate::Result;
use crate::protocols::{Protocol, tester::ProtocolTester};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TLS Fallback SCSV tester
pub struct FallbackScsvTester {
    target: Target,
    max_supported_protocol: Option<Protocol>,
    test_all_ips: bool,
}

impl FallbackScsvTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            max_supported_protocol: None,
            test_all_ips: false,
        }
    }

    /// Enable testing all resolved IP addresses (for Anycast pools)
    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    /// Test TLS_FALLBACK_SCSV support
    pub async fn test(&mut self) -> Result<FallbackScsvTestResult> {
        // First, detect the maximum supported protocol version
        tracing::debug!("Detecting maximum supported protocol version for SCSV testing");
        let protocol_tester = ProtocolTester::new(self.target.clone());

        match protocol_tester.get_preferred_protocol().await? {
            Some(max_protocol) => {
                self.max_supported_protocol = Some(max_protocol);
                tracing::debug!(
                    "Maximum supported protocol detected: {}",
                    max_protocol.name()
                );
            }
            None => {
                tracing::warn!(
                    "Could not detect any supported protocol - server may be unreachable"
                );
                return Ok(FallbackScsvTestResult {
                    supported: false,
                    accepts_downgrade: false,
                    vulnerable: false,
                    details: "Unable to detect supported protocols - server may be unreachable"
                        .to_string(),
                    has_tls13_or_higher: false,
                });
            }
        }

        // Count how many protocol versions are supported (excluding SSL 2 and QUIC)
        // SCSV is only relevant when multiple protocols are supported
        let supported_protocols = self.count_supported_protocols(&protocol_tester).await?;

        tracing::debug!(
            "Server supports {} TLS/SSL protocol version(s) (excluding SSL 2 and QUIC)",
            supported_protocols.len()
        );

        // If only one protocol version is supported, downgrade attacks are not possible
        // Match SSL Labs behavior: "Unknown (requires support for at least two protocols, excl. SSL2)"
        if supported_protocols.len() <= 1 {
            let protocol_name = self.max_supported_protocol.unwrap().name();
            let has_tls13 = matches!(self.max_supported_protocol.unwrap(), Protocol::TLS13);
            return Ok(FallbackScsvTestResult {
                supported: false,
                accepts_downgrade: false,
                vulnerable: false,
                details: format!(
                    "Downgrade attack prevention: Unknown (Server only supports {} - requires at least two protocols excluding SSL 2)",
                    protocol_name
                ),
                has_tls13_or_higher: has_tls13,
            });
        }

        // Test if server properly rejects inappropriate fallback
        // This is the definitive test for SCSV support
        let supported = self.test_rejects_inappropriate_fallback().await?;

        let accepts_downgrade = !supported;
        let vulnerable = !supported;

        // Check if TLS 1.3 or higher is supported (reduces severity)
        let has_tls13 = supported_protocols
            .iter()
            .any(|p| matches!(p, Protocol::TLS13));

        let details = if supported {
            format!(
                "TLS_FALLBACK_SCSV supported - Protected against downgrade attacks (Protocols: {})",
                self.format_protocol_list(&supported_protocols)
            )
        } else {
            format!(
                "TLS_FALLBACK_SCSV NOT supported - Vulnerable to downgrade attacks (Protocols: {})",
                self.format_protocol_list(&supported_protocols)
            )
        };

        Ok(FallbackScsvTestResult {
            supported,
            accepts_downgrade,
            vulnerable,
            details,
            has_tls13_or_higher: has_tls13,
        })
    }

    /// Count how many protocol versions the server supports
    /// Excludes SSLv2 and QUIC from the count as they don't support TLS_FALLBACK_SCSV
    async fn count_supported_protocols(
        &self,
        protocol_tester: &ProtocolTester,
    ) -> Result<Vec<Protocol>> {
        let mut supported = Vec::new();

        // Test all standard TLS/SSL protocols (excluding SSL 2 and QUIC)
        // SSL 2.0 doesn't support SCSV and shouldn't be counted (matching SSL Labs behavior)
        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::SSLv2 | Protocol::QUIC) {
                continue;
            }

            let result = protocol_tester.test_protocol(protocol).await?;
            if result.supported {
                supported.push(protocol);
                tracing::debug!("Protocol {} is supported", protocol.name());
            }
        }

        Ok(supported)
    }

    /// Format list of protocols for display
    fn format_protocol_list(&self, protocols: &[Protocol]) -> String {
        protocols
            .iter()
            .map(|p| p.name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Test if server properly rejects inappropriate fallback
    async fn test_rejects_inappropriate_fallback(&self) -> Result<bool> {
        // Determine the test version based on the maximum supported protocol
        let max_protocol = self
            .max_supported_protocol
            .expect("max_supported_protocol must be set before calling this method");

        // Get the fallback version (one version lower than max)
        let (test_version, test_version_name) = match max_protocol {
            Protocol::TLS13 => (0x0303, "TLS 1.2"), // Test with TLS 1.2
            Protocol::TLS12 => (0x0302, "TLS 1.1"), // Test with TLS 1.1
            Protocol::TLS11 => (0x0301, "TLS 1.0"), // Test with TLS 1.0
            Protocol::TLS10 => (0x0300, "SSLv3"),   // Test with SSLv3
            Protocol::SSLv3 => {
                // SSLv3 is the lowest - cannot test SCSV with anything lower
                tracing::warn!(
                    "Server only supports SSLv3 - cannot test SCSV (no lower version available)"
                );
                return Ok(false);
            }
            Protocol::SSLv2 => {
                // SSLv2 doesn't support SCSV
                tracing::warn!("Server only supports SSLv2 - SCSV not applicable");
                return Ok(false);
            }
            Protocol::QUIC => {
                // QUIC has different mechanisms
                tracing::warn!("QUIC protocol detected - SCSV testing not applicable");
                return Ok(false);
            }
        };

        tracing::debug!(
            "Testing SCSV: Max supported = {}, Testing with {} + SCSV",
            max_protocol.name(),
            test_version_name
        );

        if self.test_all_ips {
            // Test all IPs and report minimum capability (like SSL Labs)
            self.test_scsv_all_ips(test_version).await
        } else {
            // Test only first IP (default behavior)
            let addr = self.target.socket_addrs()[0];
            self.test_scsv_on_ip(test_version, addr).await
        }
    }

    /// Test SCSV on all IPs
    async fn test_scsv_all_ips(&self, test_version: u16) -> Result<bool> {
        let addrs = self.target.socket_addrs();

        if addrs.is_empty() {
            return Ok(false);
        }

        tracing::info!(
            "Testing TLS_FALLBACK_SCSV on {} IPs for hostname {}",
            addrs.len(),
            self.target.hostname
        );

        let mut all_support = true;

        for (idx, addr) in addrs.iter().enumerate() {
            let ip_supports = self.test_scsv_on_ip(test_version, *addr).await?;

            tracing::debug!(
                "IP {} ({}/{}): SCSV {} - {}",
                addr.ip(),
                idx + 1,
                addrs.len(),
                if ip_supports {
                    "supported"
                } else {
                    "NOT supported"
                },
                if ip_supports { "✓" } else { "✗" }
            );

            if !ip_supports {
                all_support = false;
            }
        }

        Ok(all_support)
    }

    /// Test SCSV on specific IP
    async fn test_scsv_on_ip(&self, test_version: u16, addr: std::net::SocketAddr) -> Result<bool> {
        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello with (max-1) version + TLS_FALLBACK_SCSV
                // This simulates an inappropriate fallback from max to max-1
                // If server properly implements SCSV, it should reject with inappropriate_fallback alert
                let client_hello = self.build_client_hello_with_scsv(test_version, true);

                tracing::debug!(
                    "Sending ClientHello with version 0x{:04x} + TLS_FALLBACK_SCSV to IP {}",
                    test_version,
                    addr.ip()
                );

                stream.write_all(&client_hello).await?;

                // Read response
                let mut buffer = vec![0u8; 8192];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        tracing::debug!(
                            "SCSV test: received {} bytes, first byte: 0x{:02x}",
                            n,
                            buffer[0]
                        );

                        // Log all bytes for debugging
                        let bytes_hex: Vec<String> =
                            buffer[..n].iter().map(|b| format!("{:02x}", b)).collect();
                        tracing::debug!("SCSV test: full response bytes: {}", bytes_hex.join(" "));

                        // Check if server sends alert (0x15) for inappropriate_fallback
                        if n > 5 && buffer[0] == 0x15 {
                            // TLS Alert structure:
                            // Byte 0: 0x15 (alert)
                            // Bytes 1-2: version
                            // Bytes 3-4: length
                            // Byte 5: alert level (0x01=warning, 0x02=fatal)
                            // Byte 6: alert description

                            let alert_level = if n > 5 { buffer[5] } else { 0 };
                            let alert_desc = if n > 6 { buffer[6] } else { 0 };

                            tracing::debug!(
                                "SCSV test: Alert level: 0x{:02x}, description: 0x{:02x}",
                                alert_level,
                                alert_desc
                            );

                            // Check for inappropriate_fallback (0x56) alert
                            let has_inappropriate_fallback_alert = alert_desc == 0x56;

                            if has_inappropriate_fallback_alert {
                                tracing::info!(
                                    "✓ Server correctly rejected inappropriate fallback with alert 0x56 (inappropriate_fallback)"
                                );
                            } else {
                                tracing::debug!(
                                    "Server sent alert 0x{:02x} (not inappropriate_fallback)",
                                    alert_desc
                                );
                            }

                            Ok(has_inappropriate_fallback_alert)
                        } else {
                            // Server accepted the fallback - not properly protected
                            tracing::warn!(
                                "✗ Server at IP {} accepted fallback (version 0x{:04x}) - NOT protected by SCSV",
                                addr.ip(),
                                test_version
                            );
                            Ok(false)
                        }
                    }
                    Ok(Ok(_)) => {
                        tracing::debug!(
                            "SCSV test: Empty response - server may have rejected connection"
                        );
                        Ok(false)
                    }
                    Err(e) => {
                        tracing::debug!("SCSV test: Timeout reading response: {}", e);
                        Ok(false)
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            "SCSV test: Error reading response: {} - Server may have closed connection",
                            e
                        );
                        Ok(false)
                    }
                }
            }
            _ => {
                tracing::debug!("SCSV test: Failed to connect to server");
                Ok(false)
            }
        }
    }

    /// Build ClientHello with or without TLS_FALLBACK_SCSV
    fn build_client_hello_with_scsv(&self, version: u16, include_scsv: bool) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(0x16);
        hello.push(((version >> 8) & 0xff) as u8);
        hello.push((version & 0xff) as u8);

        // Length placeholder
        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake: ClientHello
        hello.push(0x01);

        // Handshake length placeholder
        let hs_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client Version
        hello.push(((version >> 8) & 0xff) as u8);
        hello.push((version & 0xff) as u8);

        // Random (32 bytes)
        for i in 0..32 {
            hello.push((i * 11) as u8);
        }

        // Session ID (empty)
        hello.push(0x00);

        // Cipher Suites
        let cipher_count = if include_scsv { 3 } else { 2 };
        hello.push(0x00);
        hello.push(cipher_count * 2); // Each cipher is 2 bytes

        hello.push(0xc0);
        hello.push(0x2f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        hello.push(0x00);
        hello.push(0x9c); // TLS_RSA_WITH_AES_128_GCM_SHA256

        if include_scsv {
            // TLS_FALLBACK_SCSV (0x5600)
            hello.push(0x56);
            hello.push(0x00);
        }

        // Compression (none)
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let ext_start_pos = hello.len();
        hello.push(0x00); // Extensions length placeholder
        hello.push(0x00);

        // Add SNI extension
        hello.push(0x00); // Extension type: server_name (0)
        hello.push(0x00);

        // SNI extension length
        let sni_len = self.target.hostname.len() + 5;
        hello.push(((sni_len >> 8) & 0xff) as u8);
        hello.push((sni_len & 0xff) as u8);

        // Server name list length
        let sni_list_len = self.target.hostname.len() + 3;
        hello.push(((sni_list_len >> 8) & 0xff) as u8);
        hello.push((sni_list_len & 0xff) as u8);

        // Name type: host_name (0)
        hello.push(0x00);

        // Hostname length
        hello.push(((self.target.hostname.len() >> 8) & 0xff) as u8);
        hello.push((self.target.hostname.len() & 0xff) as u8);

        // Hostname
        hello.extend_from_slice(self.target.hostname.as_bytes());

        // Update extensions length
        let ext_len = hello.len() - ext_start_pos - 2;
        hello[ext_start_pos] = ((ext_len >> 8) & 0xff) as u8;
        hello[ext_start_pos + 1] = (ext_len & 0xff) as u8;

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        hello[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
        hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        // Update record length
        let rec_len = hello.len() - len_pos - 2;
        hello[len_pos] = ((rec_len >> 8) & 0xff) as u8;
        hello[len_pos + 1] = (rec_len & 0xff) as u8;

        hello
    }
}

/// TLS_FALLBACK_SCSV test result
#[derive(Debug, Clone)]
pub struct FallbackScsvTestResult {
    pub supported: bool,
    pub accepts_downgrade: bool,
    pub vulnerable: bool,
    pub details: String,
    pub has_tls13_or_higher: bool, // True if TLS 1.3+ supported (reduces risk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_scsv_result() {
        let result = FallbackScsvTestResult {
            supported: true,
            accepts_downgrade: false,
            vulnerable: false,
            details: "Test".to_string(),
            has_tls13_or_higher: false,
        };
        assert!(result.supported);
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_client_hello_with_scsv() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = FallbackScsvTester::new(target);
        let hello = tester.build_client_hello_with_scsv(0x0303, true);

        assert!(hello.len() > 50);
        // Check for TLS_FALLBACK_SCSV (0x5600)
        let has_scsv = hello.windows(2).any(|w| w == [0x56, 0x00]);
        assert!(has_scsv);
    }

    #[test]
    fn test_client_hello_without_scsv() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = FallbackScsvTester::new(target);
        let hello = tester.build_client_hello_with_scsv(0x0303, false);

        // Should not have TLS_FALLBACK_SCSV
        let has_scsv = hello.windows(2).any(|w| w == [0x56, 0x00]);
        assert!(!has_scsv);
    }
}
