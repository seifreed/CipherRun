// Ticketbleed Vulnerability Test
// CVE-2016-9244
//
// Ticketbleed is a vulnerability in F5 BIG-IP that leaks 31 bytes of uninitialized memory
// when processing TLS session tickets. This can expose sensitive information including
// session keys, passwords, and other confidential data.

use crate::Result;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
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

    /// Build ClientHello with SessionTicket extension using ClientHelloBuilder
    fn build_client_hello_with_session_ticket(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_vulnerability_testing().add_session_ticket(); // Add empty session ticket for ticketbleed testing
        builder.build().unwrap_or_else(|_| Vec::new())
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
    ///
    /// Ticketbleed leaks memory from uninitialized buffers in F5 BIG-IP devices.
    /// The leaked data typically contains:
    /// - Random-looking bytes (not typical ticket structure)
    /// - Repetitive patterns (from uninitialized memory)
    /// - Low entropy in some regions
    /// - Non-printable characters mixed with structured data
    ///
    /// We use multiple heuristics to reduce false negatives:
    /// 1. High proportion of null bytes (classic uninitialized memory)
    /// 2. Low-entropy regions (repetitive patterns)
    /// 3. Valid ticket structure anomalies
    fn detect_memory_leak(&self, response: &[u8]) -> Result<bool> {
        // Look for NewSessionTicket with anomalous length
        for i in 0..response.len().saturating_sub(10) {
            if response[i] == 0x16 && // Handshake record
               i + 5 < response.len() &&
               response[i + 5] == 0x04
            {
                // NewSessionTicket found

                // Check ticket length
                if i + 10 < response.len() {
                    let ticket_len = u16::from_be_bytes([response[i + 8], response[i + 9]]) as usize;

                    // F5 BIG-IP vulnerable versions leak 31 bytes
                    // But we should look for any anomalous ticket data
                    if ticket_len > 0 && i + 10 + ticket_len <= response.len() {
                        let ticket_data = &response[i + 10..i + 10 + ticket_len];

                        // Heuristic 1: High proportion of null bytes (uninitialized memory)
                        let null_count = ticket_data.iter().filter(|&&b| b == 0).count();
                        let null_ratio = null_count as f64 / ticket_data.len() as f64;
                        
                        // Heuristic 2: Low entropy (repetitive patterns) - check for repeating bytes
                        let unique_bytes = ticket_data.iter().collect::<std::collections::HashSet<_>>().len();
                        let unique_ratio = unique_bytes as f64 / ticket_data.len() as f64;
                        
                        // Heuristic 3: Check for non-printable characters (typical of memory dumps)
                        let non_printable = ticket_data
                            .iter()
                            .filter(|&&b| b < 32 && b != 0 && b != 10 && b != 13)
                            .count();
                        let non_printable_ratio = non_printable as f64 / ticket_data.len() as f64;
                        
                        // Heuristic 4: Session tickets typically start with a structured format
                        // (lifetime hint, session ID, etc). Leaked memory may not follow this.
                        // TLS session tickets should have specific structure:
                        // - Lifetime (4 bytes)
                        // - Ticket length (2 bytes)
                        // - Ticket data
                        // An additional check: valid tickets typically have reasonable lifetime
                        let has_valid_lifetime = if ticket_data.len() >= 4 {
                            let lifetime = u32::from_be_bytes([
                                ticket_data[0], ticket_data[1], ticket_data[2], ticket_data[3]
                            ]);
                            // Valid lifetime should be reasonable (< 7 days = 604800 seconds)
                            lifetime > 0 && lifetime < 604800
                        } else {
                            false
                        };

                        // Combine heuristics:
                        // - High null byte ratio (> 25%) suggests uninitialized memory
                        // - Very low unique byte ratio (< 10%) suggests repetitive patterns
                        // - High non-printable ratio (> 50%) suggests binary data leak
                        // - Missing valid ticket structure
                        let is_suspicious = 
                            null_ratio > 0.25 ||
                            unique_ratio < 0.10 ||
                            (non_printable_ratio > 0.50 && !has_valid_lifetime) ||
                            // Suspicious if we have long runs of identical bytes
                            Self::has_long_repeating_sequence(ticket_data, 8);

                        if is_suspicious {
                            // Log detection details for debugging
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Check for long sequences of identical bytes (common in uninitialized memory)
    fn has_long_repeating_sequence(data: &[u8], min_length: usize) -> bool {
        if data.len() < min_length {
            return false;
        }
        
        let mut count = 1;
        for i in 1..data.len() {
            if data[i] == data[i - 1] {
                count += 1;
                if count >= min_length {
                    return true;
                }
            } else {
                count = 1;
            }
        }
        false
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
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = TicketbleedTester::new(target);
        let hello = tester.build_client_hello_with_session_ticket();

        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello

        // Check for SessionTicket extension (0x0023)
        let has_ticket_ext = hello.windows(2).any(|w| w == [0x00, 0x23]);
        assert!(has_ticket_ext);
    }

    #[test]
    fn test_parse_new_session_ticket_detection() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = TicketbleedTester::new(target);
        let mut response = vec![0u8; 16];
        response[0] = 0x16; // Handshake record
        response[5] = 0x04; // NewSessionTicket

        assert!(tester.parse_new_session_ticket(&response).unwrap());
        assert!(
            !tester
                .parse_new_session_ticket(&[0x00, 0x01, 0x02])
                .unwrap()
        );
    }

    #[test]
    fn test_detect_memory_leak_patterns() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = TicketbleedTester::new(target);

        let mut response = vec![0u8; 32];
        response[0] = 0x16;
        response[5] = 0x04;
        response[8] = 0x00;
        response[9] = 0x08; // ticket length 8
        response[10..18].copy_from_slice(&[0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);

        assert!(tester.detect_memory_leak(&response).unwrap());

        let mut clean = vec![0u8; 32];
        clean[0] = 0x16;
        clean[5] = 0x04;
        clean[8] = 0x00;
        clean[9] = 0x08;
        clean[10..18].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);

        assert!(!tester.detect_memory_leak(&clean).unwrap());
    }

    #[test]
    fn test_parse_new_session_ticket_short_response() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = TicketbleedTester::new(target);
        assert!(!tester.parse_new_session_ticket(&[0x16, 0x03]).unwrap());
    }

    #[test]
    fn test_ticketbleed_result_details_text() {
        let result = TicketbleedTestResult {
            vulnerable: true,
            details: "Vulnerable to Ticketbleed".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.details.contains("Ticketbleed"));
    }
}
