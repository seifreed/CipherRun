// Ticketbleed Vulnerability Test
// CVE-2016-9244
//
// Ticketbleed is a vulnerability in F5 BIG-IP that leaks 31 bytes of uninitialized memory
// when processing TLS session tickets. This can expose sensitive information including
// session keys, passwords, and other confidential data.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Ticketbleed vulnerability tester
pub struct TicketbleedTester {
    target: Target,
}

/// Internal verdict from `test_session_ticket_leak` that separates conclusive
/// results from probe failures. V1 fix: a connection/timeout failure must be
/// reported as inconclusive rather than "not vulnerable".
#[derive(Debug)]
enum TicketbleedProbeOutcome {
    Vulnerable,
    NotVulnerable(&'static str),
    Inconclusive(&'static str),
}

impl TicketbleedTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Ticketbleed vulnerability
    pub async fn test(&self) -> Result<TicketbleedTestResult> {
        let outcome = self.test_session_ticket_leak().await?;

        let (vulnerable, inconclusive, details) = match outcome {
            TicketbleedProbeOutcome::Vulnerable => (
                true,
                false,
                "Vulnerable to Ticketbleed (CVE-2016-9244) - Server leaks memory in session ticket responses".to_string(),
            ),
            TicketbleedProbeOutcome::NotVulnerable(reason) => (
                false,
                false,
                format!("Not vulnerable - {}", reason),
            ),
            TicketbleedProbeOutcome::Inconclusive(reason) => (
                false,
                true,
                format!("Inconclusive - {}", reason),
            ),
        };

        Ok(TicketbleedTestResult {
            vulnerable,
            inconclusive,
            details,
        })
    }

    /// Test for session ticket memory leak
    async fn test_session_ticket_leak(&self) -> Result<TicketbleedProbeOutcome> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None).await {
            Ok(mut stream) => {
                let client_hello = self.build_client_hello_with_session_ticket();
                stream.write_all(&client_hello).await?;

                let mut buffer = vec![0u8; 16384];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let has_new_ticket = self.parse_new_session_ticket(&buffer[..n])?;

                        if has_new_ticket {
                            let client_hello2 =
                                self.build_client_hello_with_received_ticket(&buffer[..n]);
                            stream.write_all(&client_hello2).await?;

                            let mut response = vec![0u8; 16384];
                            match timeout(Duration::from_secs(3), stream.read(&mut response)).await
                            {
                                Ok(Ok(m)) if m > 0 => {
                                    let leaked = self.detect_memory_leak(&response[..m])?;
                                    if leaked {
                                        Ok(TicketbleedProbeOutcome::Vulnerable)
                                    } else {
                                        Ok(TicketbleedProbeOutcome::NotVulnerable(
                                            "No memory leak detected in session ticket handling",
                                        ))
                                    }
                                }
                                _ => Ok(TicketbleedProbeOutcome::Inconclusive(
                                    "No response to follow-up ClientHello with session ticket",
                                )),
                            }
                        } else {
                            Ok(TicketbleedProbeOutcome::NotVulnerable(
                                "Server did not issue a session ticket; vulnerability not applicable",
                            ))
                        }
                    }
                    _ => Ok(TicketbleedProbeOutcome::Inconclusive(
                        "Timeout or empty read while waiting for ServerHello/NewSessionTicket",
                    )),
                }
            }
            _ => Ok(TicketbleedProbeOutcome::Inconclusive(
                "Failed to establish TCP connection to target",
            )),
        }
    }

    /// Build ClientHello with SessionTicket extension using ClientHelloBuilder
    fn build_client_hello_with_session_ticket(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_vulnerability_testing().add_session_ticket(); // Add empty session ticket for ticketbleed testing
        builder.build().unwrap_or_else(|_| Vec::new())
    }

    /// Build ClientHello with received session ticket and truncated Session ID
    ///
    /// Ticketbleed (CVE-2016-9244) is triggered by sending a valid session ticket
    /// with a Session ID shorter than expected (1 byte instead of 32).
    /// A vulnerable server leaks uninitialized memory in the Session ID echo.
    fn build_client_hello_with_received_ticket(&self, server_response: &[u8]) -> Vec<u8> {
        // Extract the session ticket from the server's NewSessionTicket message
        let ticket = self.extract_session_ticket(server_response);

        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_vulnerability_testing();

        if let Some(ticket_data) = ticket {
            // Add the received ticket with data to trigger Ticketbleed
            builder.add_session_ticket_with_data(&ticket_data);
            // Use a 1-byte Session ID (the Ticketbleed trigger)
            builder.set_session_id(&[0x01]);
        } else {
            // Fallback: send empty ticket if extraction failed
            builder.add_session_ticket();
        }

        builder.build().unwrap_or_else(|_| Vec::new())
    }

    /// Extract session ticket data from server's NewSessionTicket message
    fn extract_session_ticket(&self, response: &[u8]) -> Option<Vec<u8>> {
        let mut offset = 0;
        while offset + 5 <= response.len() {
            let content_type = response[offset];
            let record_len =
                u16::from_be_bytes([response[offset + 3], response[offset + 4]]) as usize;
            let record_end = offset + 5 + record_len;
            if record_end > response.len() {
                break;
            }
            if content_type == 0x16 {
                let hs_start = offset + 5;
                if hs_start < record_end && response[hs_start] == 0x04 {
                    // NewSessionTicket: type(1) + length(3) + lifetime(4) + ticket_length(2) + ticket
                    if hs_start + 4 > response.len() {
                        offset = record_end;
                        continue;
                    }
                    let hs_len = ((response[hs_start + 1] as usize) << 16)
                        | ((response[hs_start + 2] as usize) << 8)
                        | (response[hs_start + 3] as usize);

                    let ticket_len_offset = hs_start + 4 + 4; // skip type+length+lifetime
                    if ticket_len_offset + 2 > response.len() {
                        offset = record_end;
                        continue;
                    }
                    let ticket_len = u16::from_be_bytes([
                        response[ticket_len_offset],
                        response[ticket_len_offset + 1],
                    ]) as usize;

                    let ticket_start = ticket_len_offset + 2;
                    let ticket_end = ticket_start + ticket_len;
                    let ticket_msg_end = hs_start + 4 + hs_len;
                    if ticket_end <= response.len()
                        && ticket_end <= ticket_msg_end
                        && ticket_end <= record_end
                        && ticket_len > 0
                        && ticket_len <= hs_len
                    {
                        return Some(response[ticket_start..ticket_end].to_vec());
                    }
                }
            }
            offset = record_end;
        }
        None
    }

    /// Parse NewSessionTicket message from server response
    fn parse_new_session_ticket(&self, response: &[u8]) -> Result<bool> {
        let mut offset = 0;
        while offset + 5 <= response.len() {
            let content_type = response[offset];
            let record_len =
                u16::from_be_bytes([response[offset + 3], response[offset + 4]]) as usize;
            let record_end = offset + 5 + record_len;
            if record_end > response.len() {
                break;
            }
            if content_type == 0x16 {
                let hs_start = offset + 5;
                if hs_start < record_end && response[hs_start] == 0x04 {
                    return Ok(true);
                }
            }
            offset = record_end;
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
        // Look for NewSessionTicket with anomalous length.
        // TLS record layout from offset i:
        //   i+0: content type (0x16), i+1-2: version, i+3-4: record len
        //   i+5: hs type (0x04), i+6-8: 3-byte hs len, i+9-12: lifetime hint
        //   i+13-14: ticket_len (u16), i+15+: ticket data
        //
        // V6 fix: validate the TLS record boundary (`record_len` at i+3..i+5)
        // before trusting bytes at fixed offsets. Previously a coincidental
        // `0x16 ... 0x04` pair in application-data would be parsed as a
        // NewSessionTicket with ticket_len read from arbitrary memory.
        for i in 0..response.len().saturating_sub(15) {
            if response[i] != 0x16 {
                continue;
            }
            if i + 5 > response.len() {
                break;
            }
            let record_len = u16::from_be_bytes([response[i + 3], response[i + 4]]) as usize;
            let record_end = i + 5 + record_len;
            if record_end > response.len() || record_len < 10 {
                // Truncated or too-short record — can't host a NewSessionTicket.
                continue;
            }
            if response[i + 5] != 0x04 {
                // Handshake type at the expected offset is not NewSessionTicket.
                continue;
            }
            // Now we know we're inside a well-formed TLS record that claims to
            // contain a NewSessionTicket handshake message. Parse its length.

            {
                let ticket_len = u16::from_be_bytes([response[i + 13], response[i + 14]]) as usize;

                // F5 BIG-IP vulnerable versions leak 31 bytes
                // But we should look for any anomalous ticket data. The ticket
                // data must also fit within the declared TLS record boundary.
                if ticket_len > 0 && i + 15 + ticket_len <= record_end {
                    // Ticketbleed leaks at least 31 bytes of uninitialized memory.
                    // Tickets shorter than 32 bytes are too small for reliable heuristic analysis.
                    if ticket_len < 32 {
                        continue;
                    }
                    let ticket_data = &response[i + 15..i + 15 + ticket_len];

                    // Heuristic 1: High proportion of null bytes (uninitialized memory)
                    let null_count = ticket_data.iter().filter(|&&b| b == 0).count();
                    let null_ratio = null_count as f64 / ticket_data.len() as f64;

                    // Heuristic 2: Low entropy (repetitive patterns) - check for repeating bytes
                    let unique_bytes = ticket_data
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len();
                    let unique_ratio = unique_bytes as f64 / ticket_data.len() as f64;

                    // Heuristic 3: Check for non-printable characters (typical of memory dumps)
                    let non_printable = ticket_data
                        .iter()
                        .filter(|&&b| b < 32 && b != 0 && b != 10 && b != 13)
                        .count();
                    let non_printable_ratio = non_printable as f64 / ticket_data.len() as f64;

                    // Heuristic 4: Valid NewSessionTicket messages have a reasonable lifetime_hint.
                    // The lifetime_hint field is at response[i+9..i+13] (NewSessionTicket envelope),
                    // NOT inside ticket_data (which is the opaque encrypted blob).
                    let has_valid_lifetime = {
                        let lifetime = u32::from_be_bytes([
                            response[i + 9],
                            response[i + 10],
                            response[i + 11],
                            response[i + 12],
                        ]);
                        // Valid lifetime should be reasonable (< 7 days = 604800 seconds)
                        lifetime > 0 && lifetime < 604800
                    };

                    // Combine heuristics:
                    // - High null byte ratio (> 25%) suggests uninitialized memory
                    // - Very low unique byte ratio (< 10%) suggests repetitive patterns
                    // - High non-printable ratio (> 50%) suggests binary data leak
                    // - Missing valid ticket structure
                    //
                    // When the ticket has a valid lifetime header, require at least 2 corroborating
                    // signals before flagging — servers that legitimately pad with zeros would
                    // otherwise produce false positives from null_ratio alone.
                    let is_suspicious = if has_valid_lifetime {
                        let signal_count = [
                            null_ratio > 0.25,
                            unique_ratio < 0.10,
                            non_printable_ratio > 0.50,
                            Self::has_long_repeating_sequence(ticket_data, 8),
                        ]
                        .iter()
                        .filter(|&&x| x)
                        .count();
                        signal_count >= 2
                    } else {
                        null_ratio > 0.25
                            || unique_ratio < 0.10
                            || non_printable_ratio > 0.50
                            || Self::has_long_repeating_sequence(ticket_data, 8)
                    };

                    if is_suspicious {
                        // Log detection details for debugging
                        return Ok(true);
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
    /// True when the probe could not reach a conclusive verdict (e.g., TCP
    /// connect failed, handshake timed out, follow-up ClientHello produced no
    /// response). Callers must not treat inconclusive results as "clean".
    pub inconclusive: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticketbleed_result() {
        let result = TicketbleedTestResult {
            vulnerable: false,
            inconclusive: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
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
        // Well-formed TLS record: content_type=0x16, version=0x03 0x03, record_len=0x00 0x01
        // Handshake: type=0x04 (NewSessionTicket)
        let mut response = vec![0u8; 16];
        response[0] = 0x16; // content_type: Handshake
        response[1] = 0x03; // version hi
        response[2] = 0x03; // version lo
        response[3] = 0x00; // record_len hi
        response[4] = 0x0b; // record_len lo = 11 (enough to hold hs type byte)
        response[5] = 0x04; // hs_type: NewSessionTicket

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

        // TLS NewSessionTicket layout from byte 0:
        //   [0]=0x16 (handshake), [1-2]=version, [3-4]=record_len
        //   [5]=0x04 (NewSessionTicket), [6-8]=hs_len, [9-12]=lifetime_hint
        //   [13-14]=ticket_len (u16), [15+]=ticket_data
        //
        // Ticketbleed leaks at least 31 bytes, so tickets shorter than 32 bytes
        // are not analysed (too small for meaningful heuristics). Use 40-byte ticket.
        //
        // V6 regression: the record_len header (bytes 3..5) must describe a real
        // TLS record that contains the handshake message. Handshake payload =
        // hs_type(1) + hs_len(3) + lifetime(4) + ticket_len(2) + ticket(40) = 50.
        const TICKET_LEN: u8 = 40;
        const RECORD_PAYLOAD: u16 = 1 + 3 + 4 + 2 + TICKET_LEN as u16;
        let mut response = vec![0u8; 5 + RECORD_PAYLOAD as usize];
        response[0] = 0x16;
        response[3] = (RECORD_PAYLOAD >> 8) as u8;
        response[4] = (RECORD_PAYLOAD & 0xff) as u8;
        response[5] = 0x04; // NewSessionTicket
        // bytes 6..9 are the 3-byte handshake length (we leave zero; not used)
        response[13] = 0x00;
        response[14] = TICKET_LEN; // ticket_len = 40
        // High null-byte ratio (> 25%) in ticket data → suspicious (memory leak pattern)
        for b in &mut response[15..15 + TICKET_LEN as usize] {
            *b = 0x00;
        }
        response[15] = 0xaa; // one non-null to avoid divide-by-zero edge case

        assert!(tester.detect_memory_leak(&response).unwrap());

        let mut clean = vec![0u8; 5 + RECORD_PAYLOAD as usize];
        clean[0] = 0x16;
        clean[3] = (RECORD_PAYLOAD >> 8) as u8;
        clean[4] = (RECORD_PAYLOAD & 0xff) as u8;
        clean[5] = 0x04;
        clean[13] = 0x00;
        clean[14] = TICKET_LEN;
        // Normal high-entropy ticket data (printable ASCII cycling) → not suspicious
        for (i, b) in clean[15..15 + TICKET_LEN as usize].iter_mut().enumerate() {
            *b = 0x41 + (i % 26) as u8; // 'A'..'Z' cycling — no nulls, no non-printable
        }

        assert!(!tester.detect_memory_leak(&clean).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_ignores_spurious_match_without_record_len() {
        // V6 regression: a buffer that contains 0x16 followed by 0x04 at offset
        // +5 but without a valid TLS record_len must NOT be misidentified as a
        // NewSessionTicket. Previously the parser trusted the byte positions
        // unconditionally and would read ticket_len from arbitrary memory.
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = TicketbleedTester::new(target);

        let mut spurious = vec![0u8; 64];
        spurious[0] = 0x16;
        spurious[3] = 0x00; // record_len = 0 → invalid record
        spurious[4] = 0x00;
        spurious[5] = 0x04; // coincidental 0x04 at the NewSessionTicket offset
        // Fill the rest with nulls so the old heuristic would have flagged as
        // "memory leak" via null_ratio.
        assert!(
            !tester.detect_memory_leak(&spurious).unwrap(),
            "record_len=0 must be rejected as malformed, not parsed"
        );
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
            inconclusive: false,
            details: "Vulnerable to Ticketbleed".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.details.contains("Ticketbleed"));
    }

    #[test]
    fn test_ticketbleed_connection_refused_is_inconclusive() {
        // V1 regression: connection failures must yield inconclusive=true, not a
        // clean "not vulnerable" verdict. We exercise the branch by targeting a
        // port guaranteed to be closed.
        use std::net::{IpAddr, Ipv4Addr};
        let target = Target::with_ips(
            "localhost".to_string(),
            1, // reserved; refuses connection
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .expect("target should build");

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let result = rt.block_on(async {
            TicketbleedTester::new(target)
                .test()
                .await
                .expect("probe should not error")
        });
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "connection-level failure must be reported as inconclusive; got details={}",
            result.details
        );
    }
}
