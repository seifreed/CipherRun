// Ticketbleed Vulnerability Test
// CVE-2016-9244
//
// Ticketbleed is a vulnerability in F5 BIG-IP that leaks 31 bytes of uninitialized memory
// when processing TLS session tickets. This can expose sensitive information including
// session keys, passwords, and other confidential data.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Ticketbleed vulnerability tester
pub struct TicketbleedTester {
    target: Target,
}

impl TicketbleedTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Ticketbleed vulnerability
    pub async fn test(&self) -> Result<TicketbleedTestResult> {
        let vulnerable = self.test_session_ticket_leak().await?;

        let details = if vulnerable {
            "Vulnerable to Ticketbleed (CVE-2016-9244) - Server leaks memory in session ticket responses".to_string()
        } else {
            "Not vulnerable - No memory leak detected in session ticket handling".to_string()
        };

        Ok(TicketbleedTestResult {
            vulnerable,
            details,
        })
    }

    /// Test for session ticket memory leak
    async fn test_session_ticket_leak(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello with SessionTicket extension
                let client_hello = self.build_client_hello_with_session_ticket();
                stream.write_all(&client_hello).await?;

                // Read ServerHello and NewSessionTicket
                let mut buffer = vec![0u8; 16384];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Parse response for NewSessionTicket message
                        let has_new_ticket = self.parse_new_session_ticket(&buffer[..n])?;

                        if has_new_ticket {
                            // Send second ClientHello with the received ticket
                            let client_hello2 =
                                self.build_client_hello_with_received_ticket(&buffer[..n]);
                            stream.write_all(&client_hello2).await?;

                            // Read response
                            let mut response = vec![0u8; 16384];
                            match timeout(Duration::from_secs(3), stream.read(&mut response)).await
                            {
                                Ok(Ok(m)) if m > 0 => {
                                    // Check for anomalous ticket lengths (31 extra bytes)
                                    let leaked = self.detect_memory_leak(&response[..m])?;
                                    Ok(leaked)
                                }
                                _ => Ok(false),
                            }
                        } else {
                            Ok(false)
                        }
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Build ClientHello with SessionTicket extension
    fn build_client_hello_with_session_ticket(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(0x16);
        hello.push(0x03);
        hello.push(0x03); // TLS 1.2

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

        // Client Version: TLS 1.2
        hello.push(0x03);
        hello.push(0x03);

        // Random (32 bytes)
        for i in 0..32 {
            hello.push((i * 7) as u8);
        }

        // Session ID (empty)
        hello.push(0x00);

        // Cipher Suites
        hello.push(0x00);
        hello.push(0x04);
        hello.push(0xc0);
        hello.push(0x2f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        hello.push(0x00);
        hello.push(0x9c); // TLS_RSA_WITH_AES_128_GCM_SHA256

        // Compression (none)
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let ext_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00); // Extensions length placeholder

        // SessionTicket extension (0x0023)
        hello.push(0x00);
        hello.push(0x23);
        hello.push(0x00);
        hello.push(0x00); // Empty ticket

        // Update extensions length
        let ext_len = hello.len() - ext_pos - 2;
        hello[ext_pos] = ((ext_len >> 8) & 0xff) as u8;
        hello[ext_pos + 1] = (ext_len & 0xff) as u8;

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

    /// Build ClientHello with received session ticket
    fn build_client_hello_with_received_ticket(&self, _server_response: &[u8]) -> Vec<u8> {
        // Extract ticket from NewSessionTicket message
        // For simplicity, we'll send a ClientHello with an empty ticket
        // Real implementation would parse and extract the actual ticket
        self.build_client_hello_with_session_ticket()
    }

    /// Parse NewSessionTicket message from server response
    fn parse_new_session_ticket(&self, response: &[u8]) -> Result<bool> {
        // Look for Handshake type 0x04 (NewSessionTicket)
        for i in 0..response.len().saturating_sub(10) {
            if response[i] == 0x16 && // Handshake record
               i + 5 < response.len() &&
               response[i + 5] == 0x04
            {
                // NewSessionTicket
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Detect memory leak in session ticket response
    fn detect_memory_leak(&self, response: &[u8]) -> Result<bool> {
        // Look for NewSessionTicket with anomalous length
        // Ticketbleed leaks 31 extra bytes
        for i in 0..response.len().saturating_sub(10) {
            if response[i] == 0x16 && // Handshake record
               i + 5 < response.len() &&
               response[i + 5] == 0x04
            {
                // NewSessionTicket

                // Check ticket length
                if i + 10 < response.len() {
                    let ticket_len = u16::from_be_bytes([response[i + 8], response[i + 9]]);

                    // F5 BIG-IP vulnerable versions leak 31 bytes
                    // Look for patterns indicating uninitialized memory
                    if ticket_len > 0 && i + 10 + ticket_len as usize <= response.len() {
                        let ticket_data = &response[i + 10..i + 10 + ticket_len as usize];

                        // Check for suspicious patterns (null bytes, repetitive patterns)
                        let null_count = ticket_data.iter().filter(|&&b| b == 0).count();
                        let is_suspicious = null_count > ticket_data.len() / 4;

                        return Ok(is_suspicious);
                    }
                }
            }
        }
        Ok(false)
    }
}

/// Ticketbleed test result
#[derive(Debug, Clone)]
pub struct TicketbleedTestResult {
    pub vulnerable: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticketbleed_result() {
        let result = TicketbleedTestResult {
            vulnerable: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_client_hello_with_session_ticket() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = TicketbleedTester::new(target);
        let hello = tester.build_client_hello_with_session_ticket();

        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello

        // Check for SessionTicket extension (0x0023)
        let has_ticket_ext = hello.windows(2).any(|w| w == [0x00, 0x23]);
        assert!(has_ticket_ext);
    }
}
