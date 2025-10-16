// TLS Fallback SCSV (Signaling Cipher Suite Value) Testing
// RFC 7507 - TLS_FALLBACK_SCSV prevents protocol downgrade attacks
// Protects against attacks like POODLE by preventing fallback to older protocols

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TLS Fallback SCSV tester
pub struct FallbackScsvTester {
    target: Target,
}

impl FallbackScsvTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test TLS_FALLBACK_SCSV support
    pub async fn test(&self) -> Result<FallbackScsvTestResult> {
        // Test if server properly rejects inappropriate fallback
        // This is the definitive test for SCSV support
        let supported = self.test_rejects_inappropriate_fallback().await?;

        let accepts_downgrade = !supported;
        let vulnerable = !supported;

        let details = if supported {
            "TLS_FALLBACK_SCSV supported - Protected against downgrade attacks".to_string()
        } else {
            "TLS_FALLBACK_SCSV NOT supported - Vulnerable to downgrade attacks".to_string()
        };

        Ok(FallbackScsvTestResult {
            supported,
            accepts_downgrade,
            vulnerable,
            details,
        })
    }

    /// Test if server properly rejects inappropriate fallback
    async fn test_rejects_inappropriate_fallback(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello with TLS 1.2 + TLS_FALLBACK_SCSV
                // This simulates fallback from TLS 1.3 to 1.2
                // If server supports TLS 1.3, it should reject with inappropriate_fallback
                let client_hello = self.build_client_hello_with_scsv(0x0303, true);
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

                            tracing::debug!(
                                "SCSV test: Got alert, inappropriate_fallback: {}",
                                has_inappropriate_fallback_alert
                            );
                            Ok(has_inappropriate_fallback_alert)
                        } else {
                            // Server accepted the fallback - not properly protected
                            tracing::debug!("SCSV test: Server accepted fallback (no alert)");
                            Ok(false)
                        }
                    }
                    Ok(Ok(_)) => {
                        tracing::debug!("SCSV test: Empty response");
                        Ok(false)
                    }
                    Err(e) => {
                        tracing::debug!("SCSV test: Timeout/error: {}", e);
                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
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
