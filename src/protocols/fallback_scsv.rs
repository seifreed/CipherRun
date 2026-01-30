// TLS Fallback SCSV (Signaling Cipher Suite Value) Testing
// RFC 7507 - TLS_FALLBACK_SCSV prevents protocol downgrade attacks
// Protects against attacks like POODLE by preventing fallback to older protocols

use crate::Result;
use crate::constants::{
    COMPRESSION_NULL, CONTENT_TYPE_ALERT, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO,
};
use crate::protocols::{Protocol, tester::ProtocolTester};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TLS Fallback SCSV tester
pub struct FallbackScsvTester<'a> {
    target: &'a Target,
    max_supported_protocol: Option<Protocol>,
    test_all_ips: bool,
}

impl<'a> FallbackScsvTester<'a> {
    pub fn new(target: &'a Target) -> Self {
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
            let max_protocol = self.max_supported_protocol.ok_or_else(|| {
                anyhow::anyhow!("max_supported_protocol is None when it should be Some")
            })?;
            let protocol_name = max_protocol.name();
            let has_tls13 = matches!(max_protocol, Protocol::TLS13);
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
        let supported = self
            .test_rejects_inappropriate_fallback(&supported_protocols)
            .await?;

        let accepts_downgrade = supported.accepts_downgrade;
        let vulnerable = supported.vulnerable;

        // Check if TLS 1.3 or higher is supported (reduces severity)
        let has_tls13 = supported_protocols
            .iter()
            .any(|p| matches!(p, Protocol::TLS13));

        let details = if supported.supported {
            format!(
                "TLS_FALLBACK_SCSV supported - Protected against downgrade attacks (Protocols: {})",
                self.format_protocol_list(&supported_protocols)
            )
        } else if supported.inconclusive {
            format!(
                "Downgrade attack prevention: Inconclusive (fallback test did not complete cleanly) (Protocols: {})",
                self.format_protocol_list(&supported_protocols)
            )
        } else {
            format!(
                "TLS_FALLBACK_SCSV NOT supported - Vulnerable to downgrade attacks (Protocols: {})",
                self.format_protocol_list(&supported_protocols)
            )
        };

        Ok(FallbackScsvTestResult {
            supported: supported.supported,
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

    /// Select the highest supported protocol below the maximum
    fn select_fallback_protocol(
        &self,
        supported_protocols: &[Protocol],
        max_protocol: Protocol,
    ) -> Option<Protocol> {
        supported_protocols
            .iter()
            .copied()
            .filter(|protocol| *protocol < max_protocol)
            .max()
    }

    /// Test if server properly rejects inappropriate fallback
    async fn test_rejects_inappropriate_fallback(
        &self,
        supported_protocols: &[Protocol],
    ) -> Result<ScsvSupport> {
        // Determine the test version based on the maximum supported protocol
        let max_protocol = self
            .max_supported_protocol
            .expect("max_supported_protocol must be set before calling this method");

        // Get the fallback version (highest supported protocol below max)
        let fallback_protocol = match max_protocol {
            Protocol::SSLv3 => {
                // SSLv3 is the lowest - cannot test SCSV with anything lower
                tracing::warn!(
                    "Server only supports SSLv3 - cannot test SCSV (no lower version available)"
                );
                return Ok(ScsvSupport::not_supported());
            }
            Protocol::SSLv2 => {
                // SSLv2 doesn't support SCSV
                tracing::warn!("Server only supports SSLv2 - SCSV not applicable");
                return Ok(ScsvSupport::not_supported());
            }
            Protocol::QUIC => {
                // QUIC has different mechanisms
                tracing::warn!("QUIC protocol detected - SCSV testing not applicable");
                return Ok(ScsvSupport::not_supported());
            }
            _ => {
                let fallback = self.select_fallback_protocol(supported_protocols, max_protocol);
                let Some(fallback) = fallback else {
                    tracing::warn!(
                        "No lower supported protocol found for SCSV test - cannot test fallback"
                    );
                    return Ok(ScsvSupport::inconclusive());
                };
                fallback
            }
        };

        let test_version = fallback_protocol.as_hex();
        let test_version_name = fallback_protocol.name();

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
    async fn test_scsv_all_ips(&self, test_version: u16) -> Result<ScsvSupport> {
        let addrs = self.target.socket_addrs();

        if addrs.is_empty() {
            return Ok(ScsvSupport::inconclusive());
        }

        tracing::info!(
            "Testing TLS_FALLBACK_SCSV on {} IPs for hostname {}",
            addrs.len(),
            self.target.hostname
        );

        let mut all_support = true;
        let mut inconclusive = false;

        for (idx, addr) in addrs.iter().enumerate() {
            let ip_supports = self.test_scsv_on_ip(test_version, *addr).await?;

            tracing::debug!(
                "IP {} ({}/{}): SCSV {} - {}",
                addr.ip(),
                idx + 1,
                addrs.len(),
                if ip_supports.supported {
                    "supported"
                } else {
                    "NOT supported"
                },
                if ip_supports.supported { "✓" } else { "✗" }
            );

            if ip_supports.inconclusive {
                inconclusive = true;
            }

            if !ip_supports.supported {
                all_support = false;
            }
        }

        if inconclusive {
            Ok(ScsvSupport::inconclusive())
        } else if all_support {
            Ok(ScsvSupport::supported())
        } else {
            Ok(ScsvSupport::not_supported())
        }
    }

    /// Test SCSV on specific IP
    async fn test_scsv_on_ip(
        &self,
        test_version: u16,
        addr: std::net::SocketAddr,
    ) -> Result<ScsvSupport> {
        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello with (max-1) version WITHOUT SCSV first
                // If this fails, the SCSV result is inconclusive (fallback path not viable)
                let client_hello_no_scsv = self.build_client_hello_with_scsv(test_version, false);

                tracing::debug!(
                    "Sending ClientHello with version 0x{:04x} (no SCSV) to IP {}",
                    test_version,
                    addr.ip()
                );

                stream.write_all(&client_hello_no_scsv).await?;

                let mut buffer = vec![0u8; 8192];
                let baseline = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;
                if !self.baseline_fallback_accepted(baseline, &buffer) {
                    tracing::debug!(
                        "SCSV test: baseline fallback without SCSV did not complete cleanly"
                    );
                    return Ok(ScsvSupport::inconclusive());
                }

                // Reconnect and test with SCSV
                let stream = timeout(Duration::from_secs(5), TcpStream::connect(addr)).await;
                let Ok(Ok(mut stream)) = stream else {
                    tracing::debug!("SCSV test: Failed to reconnect for SCSV test");
                    return Ok(ScsvSupport::inconclusive());
                };

                let client_hello_scsv = self.build_client_hello_with_scsv(test_version, true);

                tracing::debug!(
                    "Sending ClientHello with version 0x{:04x} + TLS_FALLBACK_SCSV to IP {}",
                    test_version,
                    addr.ip()
                );

                stream.write_all(&client_hello_scsv).await?;

                let mut buffer = vec![0u8; 8192];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        tracing::debug!(
                            "SCSV test: received {} bytes, first byte: 0x{:02x}",
                            n,
                            buffer[0]
                        );

                        let bytes_hex: Vec<String> =
                            buffer[..n].iter().map(|b| format!("{:02x}", b)).collect();
                        tracing::debug!("SCSV test: full response bytes: {}", bytes_hex.join(" "));

                        // TLS Alert structure requires at least 7 bytes:
                        // Byte 0: Content Type (CONTENT_TYPE_ALERT = 0x15)
                        // Bytes 1-2: Version
                        // Bytes 3-4: Length
                        // Byte 5: Alert Level
                        // Byte 6: Alert Description
                        if n > 6 && buffer[0] == CONTENT_TYPE_ALERT {
                            let alert_level = buffer[5];
                            let alert_desc = buffer[6];

                            tracing::debug!(
                                "SCSV test: Alert level: 0x{:02x}, description: 0x{:02x}",
                                alert_level,
                                alert_desc
                            );

                            let has_inappropriate_fallback_alert = alert_desc == 0x56;

                            if has_inappropriate_fallback_alert {
                                tracing::info!(
                                    "✓ Server correctly rejected inappropriate fallback with alert 0x56 (inappropriate_fallback)"
                                );
                                Ok(ScsvSupport::supported())
                            } else {
                                tracing::debug!(
                                    "Server sent alert 0x{:02x} (not inappropriate_fallback)",
                                    alert_desc
                                );
                                Ok(ScsvSupport::not_supported())
                            }
                        } else {
                            tracing::warn!(
                                "✗ Server at IP {} accepted fallback (version 0x{:04x}) - NOT protected by SCSV",
                                addr.ip(),
                                test_version
                            );
                            Ok(ScsvSupport::not_supported())
                        }
                    }
                    Ok(Ok(_)) => {
                        tracing::debug!(
                            "SCSV test: Empty response - server may have rejected connection"
                        );
                        Ok(ScsvSupport::inconclusive())
                    }
                    Err(e) => {
                        tracing::debug!("SCSV test: Timeout reading response: {}", e);
                        Ok(ScsvSupport::inconclusive())
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            "SCSV test: Error reading response: {} - Server may have closed connection",
                            e
                        );
                        Ok(ScsvSupport::inconclusive())
                    }
                }
            }
            _ => {
                tracing::debug!("SCSV test: Failed to connect to server");
                Ok(ScsvSupport::inconclusive())
            }
        }
    }

    /// Build ClientHello with or without TLS_FALLBACK_SCSV
    fn build_client_hello_with_scsv(&self, version: u16, include_scsv: bool) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(CONTENT_TYPE_HANDSHAKE); // 0x16
        hello.push(((version >> 8) & 0xff) as u8);
        hello.push((version & 0xff) as u8);

        // Length placeholder
        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake: ClientHello
        hello.push(HANDSHAKE_TYPE_CLIENT_HELLO); // 0x01

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
        hello.push(0x01); // 1 compression method
        hello.push(COMPRESSION_NULL); // 0x00

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

#[derive(Debug, Clone, Copy)]
struct ScsvSupport {
    supported: bool,
    vulnerable: bool,
    accepts_downgrade: bool,
    inconclusive: bool,
}

impl ScsvSupport {
    fn supported() -> Self {
        Self {
            supported: true,
            vulnerable: false,
            accepts_downgrade: false,
            inconclusive: false,
        }
    }

    fn not_supported() -> Self {
        Self {
            supported: false,
            vulnerable: true,
            accepts_downgrade: true,
            inconclusive: false,
        }
    }

    fn inconclusive() -> Self {
        Self {
            supported: false,
            vulnerable: false,
            accepts_downgrade: false,
            inconclusive: true,
        }
    }
}

impl FallbackScsvTester<'_> {
    fn baseline_fallback_accepted(
        &self,
        read_result: std::result::Result<
            std::result::Result<usize, std::io::Error>,
            tokio::time::error::Elapsed,
        >,
        buffer: &[u8],
    ) -> bool {
        match read_result {
            Ok(Ok(n)) if n > 0 => {
                // If we got an alert immediately without SCSV, baseline failed.
                // Alert record requires at least 7 bytes (header + level + desc)
                if n > 6 && buffer[0] == CONTENT_TYPE_ALERT {
                    return false;
                }
                true
            }
            _ => false,
        }
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
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(0x0303, true);

        assert!(hello.len() > 50);
        // Check for TLS_FALLBACK_SCSV (0x5600)
        let has_scsv = hello.windows(2).any(|w| w == [0x56, 0x00]);
        assert!(has_scsv);
    }

    #[test]
    fn test_client_hello_without_scsv() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = FallbackScsvTester::new(&target);
        let hello = tester.build_client_hello_with_scsv(0x0303, false);

        // Should not have TLS_FALLBACK_SCSV
        let has_scsv = hello.windows(2).any(|w| w == [0x56, 0x00]);
        assert!(!has_scsv);
    }
}
