// Ticketbleed Vulnerability Test
// CVE-2016-9244
//
// Ticketbleed is a vulnerability in F5 BIG-IP that leaks 31 bytes of uninitialized memory
// when processing TLS session tickets. This can expose sensitive information including
// session keys, passwords, and other confidential data.

use crate::Result;
use crate::constants::{CONTENT_TYPE_HANDSHAKE, TLS_HANDSHAKE_TIMEOUT};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Distinctive 16-byte Session ID sent in the resumption ClientHello.
///
/// A Ticketbleed-vulnerable F5 BIG-IP echoes a full 32-byte Session ID in its
/// ServerHello — beginning with whatever the client sent and padding the
/// remainder with uninitialized memory. Using a 16-byte marker makes a
/// coincidental "echo" from a healthy server (which would have to generate a
/// fresh Session ID matching all 16 bytes) astronomically unlikely (2^-128),
/// so the leak check below cannot false-positive.
const TICKETBLEED_SESSION_ID_MARKER: [u8; 16] = [
    0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

fn read_u24_at(data: &[u8], offset: usize) -> Option<usize> {
    data.get(offset..offset.checked_add(3)?)
        .and_then(|bytes| <&[u8; 3]>::try_from(bytes).ok())
        .map(|bytes| {
            let [high, mid, low] = *bytes;
            u32::from_be_bytes([0, high, mid, low]) as usize
        })
}

#[cfg(test)]
fn write_u24_at(data: &mut [u8], offset: usize, value: usize) {
    data.get_mut(offset..offset + 3)
        .expect("test fixture should contain u24 placeholder")
        .copy_from_slice(&[
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]);
}

/// Ticketbleed vulnerability tester
pub struct TicketbleedTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
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
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before the Ticketbleed probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
    }

    /// Connect, upgrading via STARTTLS first for plaintext-first services.
    async fn starttls_connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<tokio::net::TcpStream> {
        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        crate::utils::network::connect_with_starttls(addr, timeout, self.starttls, &hostname).await
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

        match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(mut stream) => {
                let client_hello = self.build_client_hello_with_session_ticket()?;
                stream.write_all(&client_hello).await?;

                let mut buffer = vec![0u8; 16384];
                let n = self
                    .read_until_new_session_ticket(&mut stream, &mut buffer, Duration::from_secs(3))
                    .await;
                match n {
                    n if n > 0 => {
                        let server_response =
                            buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                                message: "Ticketbleed ticket response read length exceeded buffer"
                                    .to_string(),
                            })?;
                        let has_new_ticket = match self.parse_new_session_ticket(server_response) {
                            Ok(value) => value,
                            Err(_) => {
                                return Ok(TicketbleedProbeOutcome::Inconclusive(
                                    "Malformed session ticket response",
                                ));
                            }
                        };

                        if has_new_ticket {
                            let client_hello2 = match self
                                .build_client_hello_with_received_ticket(server_response)
                            {
                                Ok(value) => value,
                                Err(_) => {
                                    return Ok(TicketbleedProbeOutcome::Inconclusive(
                                        "Malformed session ticket response",
                                    ));
                                }
                            };
                            stream.write_all(&client_hello2).await?;

                            let mut response = vec![0u8; 16384];
                            match timeout(Duration::from_secs(3), stream.read(&mut response)).await
                            {
                                Ok(Ok(m)) if m > 0 => {
                                    let resumed_response = response.get(..m).ok_or_else(|| {
                                        crate::TlsError::ParseError {
                                            message:
                                                "Ticketbleed resumed response read length exceeded buffer"
                                                    .to_string(),
                                        }
                                    })?;
                                    let leaked = self.detect_memory_leak(resumed_response)?;
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

    async fn read_until_new_session_ticket(
        &self,
        stream: &mut tokio::net::TcpStream,
        buffer: &mut [u8],
        per_read_timeout: Duration,
    ) -> usize {
        let mut total = 0usize;
        loop {
            if total >= buffer.len() {
                break;
            }
            let Some(read_buffer) = buffer.get_mut(total..) else {
                break;
            };
            let n = match timeout(per_read_timeout, stream.read(read_buffer)).await {
                Ok(Ok(n)) => n,
                _ => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            let Some(accumulated) = buffer.get(..total) else {
                break;
            };
            match self.parse_new_session_ticket(accumulated) {
                Ok(true) => break,
                Ok(false) => {}
                Err(_) => {}
            }
        }
        total
    }

    /// Build ClientHello with SessionTicket extension using ClientHelloBuilder
    fn build_client_hello_with_session_ticket(&self) -> Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_vulnerability_testing().add_session_ticket(); // Add empty session ticket for ticketbleed testing
        builder.build()
    }

    /// Build ClientHello with the received session ticket and a short marker
    /// Session ID.
    ///
    /// Ticketbleed (CVE-2016-9244) is triggered by sending a valid session ticket
    /// alongside a Session ID shorter than 32 bytes. A vulnerable F5 BIG-IP leaks
    /// uninitialized memory by padding its echoed Session ID back out to 32 bytes.
    fn build_client_hello_with_received_ticket(&self, server_response: &[u8]) -> Result<Vec<u8>> {
        // Extract the session ticket from the server's NewSessionTicket message
        let ticket = self.extract_session_ticket(server_response)?;

        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_vulnerability_testing();

        if let Some(ticket_data) = ticket {
            // Add the received ticket with data to trigger Ticketbleed
            builder.add_session_ticket_with_data(&ticket_data);
            // Send the distinctive marker Session ID. A vulnerable F5 echoes it
            // back padded to 32 bytes with leaked memory (see detect_memory_leak).
            builder.set_session_id(&TICKETBLEED_SESSION_ID_MARKER);
        } else {
            // Fallback: send empty ticket if extraction failed
            builder.add_session_ticket();
        }

        builder.build()
    }

    /// Extract session ticket data from server's NewSessionTicket message
    fn extract_session_ticket(&self, response: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut offset = 0usize;
        while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= response.len()) {
            let header = response
                .get(offset..header_end)
                .and_then(|header| <&[u8; 5]>::try_from(header).ok())
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "Ticketbleed ticket TLS record header truncated".to_string(),
                })?;
            let [content_type, _, _, len_high, len_low] = *header;
            let record_len = u16::from_be_bytes([len_high, len_low]) as usize;
            let record_end =
                header_end
                    .checked_add(record_len)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Ticketbleed ticket TLS record length overflow".to_string(),
                    })?;
            if record_end > response.len() {
                return Err(crate::TlsError::ParseError {
                    message: "Ticketbleed ticket TLS record length exceeds available data"
                        .to_string(),
                });
            }
            if content_type == 0x16 {
                let mut hs_start = header_end;
                while let Some(hs_body_start) =
                    hs_start.checked_add(4).filter(|&end| end <= record_end)
                {
                    // NewSessionTicket: type(1) + length(3) + lifetime(4) + ticket_length(2) + ticket
                    let hs_len_offset =
                        hs_start
                            .checked_add(1)
                            .ok_or_else(|| crate::TlsError::ParseError {
                                message: "Ticketbleed ticket handshake length offset overflow"
                                    .to_string(),
                            })?;
                    let hs_len = read_u24_at(response, hs_len_offset).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ticket handshake length truncated".to_string(),
                        }
                    })?;
                    let hs_end = hs_body_start.checked_add(hs_len).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ticket handshake length overflow".to_string(),
                        }
                    })?;
                    if hs_end > record_end {
                        return Err(crate::TlsError::ParseError {
                            message: "Ticketbleed ticket handshake length exceeds record"
                                .to_string(),
                        });
                    }
                    if response.get(hs_start) != Some(&0x04) {
                        hs_start = hs_end;
                        continue;
                    }

                    let ticket_len_offset = hs_body_start.checked_add(4).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ticket lifetime offset overflow".to_string(),
                        }
                    })?; // skip lifetime
                    let ticket_len_end = ticket_len_offset.checked_add(2).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ticket length offset overflow".to_string(),
                        }
                    })?;
                    if ticket_len_end > hs_end {
                        return Err(crate::TlsError::ParseError {
                            message: "Ticketbleed ticket length truncated".to_string(),
                        });
                    }
                    let ticket_len = read_u16_at(response, ticket_len_offset)
                        .map(usize::from)
                        .ok_or_else(|| crate::TlsError::ParseError {
                            message: "Ticketbleed ticket length truncated".to_string(),
                        })?;

                    let ticket_start = ticket_len_end;
                    let ticket_end = ticket_start.checked_add(ticket_len).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ticket length overflow".to_string(),
                        }
                    })?;
                    if ticket_len == 0 {
                        return Ok(None);
                    }
                    if ticket_end > hs_end || ticket_end > record_end {
                        return Err(crate::TlsError::ParseError {
                            message: "Ticketbleed ticket data exceeds handshake".to_string(),
                        });
                    }
                    return response
                        .get(ticket_start..ticket_end)
                        .map(|ticket| Ok(Some(ticket.to_vec())))
                        .unwrap_or_else(|| {
                            Err(crate::TlsError::ParseError {
                                message: "Ticketbleed ticket data truncated".to_string(),
                            })
                        });
                }
                if hs_start != record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed ticket handshake header truncated".to_string(),
                    });
                }
            }
            offset = record_end;
        }
        if offset != response.len() {
            if offset == 0 && response.first() != Some(&0x16) {
                return Ok(None);
            }
            return Err(crate::TlsError::ParseError {
                message: "Ticketbleed ticket TLS record header truncated".to_string(),
            });
        }
        Ok(None)
    }

    /// Parse NewSessionTicket message from server response
    fn parse_new_session_ticket(&self, response: &[u8]) -> Result<bool> {
        let mut offset = 0usize;
        while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= response.len()) {
            let header = response
                .get(offset..header_end)
                .and_then(|header| <&[u8; 5]>::try_from(header).ok())
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "Ticketbleed TLS record header truncated".to_string(),
                })?;
            let [content_type, _, _, len_high, len_low] = *header;
            let record_len = u16::from_be_bytes([len_high, len_low]) as usize;
            let record_end =
                header_end
                    .checked_add(record_len)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Ticketbleed TLS record length overflow".to_string(),
                    })?;
            if record_end > response.len() {
                return Err(crate::TlsError::ParseError {
                    message: "Ticketbleed TLS record length exceeds available data".to_string(),
                });
            }
            if content_type == 0x16 {
                let mut hs_start = header_end;
                while let Some(hs_body_start) =
                    hs_start.checked_add(4).filter(|&end| end <= record_end)
                {
                    let hs_len_offset =
                        hs_start
                            .checked_add(1)
                            .ok_or_else(|| crate::TlsError::ParseError {
                                message: "Ticketbleed handshake length offset overflow".to_string(),
                            })?;
                    let hs_len = read_u24_at(response, hs_len_offset).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed handshake length truncated".to_string(),
                        }
                    })?;
                    let hs_end = hs_body_start.checked_add(hs_len).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed handshake length overflow".to_string(),
                        }
                    })?;
                    if hs_end > record_end {
                        return Err(crate::TlsError::ParseError {
                            message: "Ticketbleed handshake length exceeds record".to_string(),
                        });
                    }
                    if response.get(hs_start) == Some(&0x04) {
                        return Ok(true);
                    }
                    hs_start = hs_end;
                }
                if hs_start != record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed NewSessionTicket header truncated".to_string(),
                    });
                }
            }
            offset = record_end;
        }
        if offset != response.len() {
            if offset == 0 && response.first() != Some(&0x16) {
                return Ok(false);
            }
            return Err(crate::TlsError::ParseError {
                message: "Ticketbleed TLS record header truncated".to_string(),
            });
        }
        Ok(false)
    }

    /// Extract the Session ID echoed in the server's ServerHello, if present.
    ///
    /// Walks TLS records looking for a Handshake record whose first message is a
    /// ServerHello (handshake type `0x02`) and returns its `session_id` field.
    /// Every offset is bounds-checked against both the declared record length
    /// and the buffer, so a malformed/truncated TLS response is returned as an
    /// error rather than being reported as "not vulnerable".
    fn extract_serverhello_session_id(response: &[u8]) -> Result<Option<&[u8]>> {
        let mut offset = 0usize;
        while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= response.len()) {
            let record_len_offset =
                offset
                    .checked_add(3)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello record length offset overflow"
                            .to_string(),
                    })?;
            let record_len = read_u16_at(response, record_len_offset)
                .map(usize::from)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "Ticketbleed ServerHello record length truncated".to_string(),
                })?;
            let record_end =
                header_end
                    .checked_add(record_len)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello record length overflow".to_string(),
                    })?;
            if record_end > response.len() {
                return Err(crate::TlsError::ParseError {
                    message: "Ticketbleed ServerHello record length exceeds available data"
                        .to_string(),
                });
            }
            if response.get(offset) == Some(&CONTENT_TYPE_HANDSHAKE) {
                let mut hs_start = header_end;
                while let Some(hs_body_start) =
                    hs_start.checked_add(4).filter(|&end| end <= record_end)
                {
                    let hs_len = read_u24_at(response, hs_start + 1).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ServerHello handshake length truncated"
                                .to_string(),
                        }
                    })?;
                    let hs_end = hs_body_start.checked_add(hs_len).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ServerHello handshake length overflow"
                                .to_string(),
                        }
                    })?;
                    if hs_end > record_end {
                        return Err(crate::TlsError::ParseError {
                            message: "Ticketbleed ServerHello handshake length exceeds record"
                                .to_string(),
                        });
                    }
                    if response.get(hs_start) != Some(&0x02) {
                        hs_start = hs_end;
                        continue;
                    }

                    // ServerHello body: version(2) + random(32) + session_id_length(1) + session_id(..)
                    let session_id_len_pos =
                        hs_body_start.checked_add(2 + 32).ok_or_else(|| {
                            crate::TlsError::ParseError {
                                message: "Ticketbleed ServerHello session ID offset overflow"
                                    .to_string(),
                            }
                        })?;
                    let session_id_len = response
                        .get(session_id_len_pos)
                        .copied()
                        .map(usize::from)
                        .ok_or_else(|| crate::TlsError::ParseError {
                            message: "Ticketbleed ServerHello session ID length truncated"
                                .to_string(),
                        })?;
                    let session_id_start = session_id_len_pos.checked_add(1).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "Ticketbleed ServerHello session ID start overflow"
                                .to_string(),
                        }
                    })?;
                    let session_id_end =
                        session_id_start
                            .checked_add(session_id_len)
                            .ok_or_else(|| crate::TlsError::ParseError {
                                message: "Ticketbleed ServerHello session ID length overflow"
                                    .to_string(),
                            })?;
                    if session_id_end <= hs_end {
                        return response.get(session_id_start..session_id_end).map_or_else(
                            || {
                                Err(crate::TlsError::ParseError {
                                    message: "Ticketbleed ServerHello session ID truncated"
                                        .to_string(),
                                })
                            },
                            |session_id| Ok(Some(session_id)),
                        );
                    }
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello session ID exceeds handshake".to_string(),
                    });
                }
                if hs_start != record_end {
                    return Err(crate::TlsError::ParseError {
                        message: "Ticketbleed ServerHello handshake header truncated".to_string(),
                    });
                }
            }
            offset = record_end;
        }
        if offset != response.len() {
            if offset == 0 && response.first() != Some(&CONTENT_TYPE_HANDSHAKE) {
                return Ok(None);
            }
            return Err(crate::TlsError::ParseError {
                message: "Ticketbleed ServerHello record header truncated".to_string(),
            });
        }
        Ok(None)
    }

    /// Detect a Ticketbleed memory leak in the server's resumption response.
    ///
    /// CVE-2016-9244: a vulnerable F5 BIG-IP echoes a full 32-byte Session ID in
    /// its ServerHello even though the resumption ClientHello carried only the
    /// 16-byte [`TICKETBLEED_SESSION_ID_MARKER`], padding the remaining bytes
    /// with uninitialized memory. The leak therefore presents as an echoed
    /// Session ID that *begins with* our marker but is *longer than* it.
    ///
    /// A healthy server either echoes the marker at its exact 16-byte length, or
    /// negotiates a fresh session whose 32-byte Session ID will not begin with
    /// the marker — so this check cannot false-positive (a coincidental 16-byte
    /// prefix match has probability 2^-128).
    fn detect_memory_leak(&self, response: &[u8]) -> Result<bool> {
        Ok(
            Self::extract_serverhello_session_id(response)?.is_some_and(|session_id| {
                session_id.len() > TICKETBLEED_SESSION_ID_MARKER.len()
                    && session_id.starts_with(&TICKETBLEED_SESSION_ID_MARKER)
            }),
        )
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        let hello = tester
            .build_client_hello_with_session_ticket()
            .expect("ClientHello should build");

        assert!(hello.len() > 50);
        assert_eq!(hello.first(), Some(&0x16)); // Handshake
        assert_eq!(hello.get(5), Some(&0x01)); // ClientHello

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
        response
            .get_mut(..6)
            .expect("test response should contain TLS header")
            .copy_from_slice(&[
                0x16, // content_type: Handshake
                0x03, // version hi
                0x03, // version lo
                0x00, // record_len hi
                0x0b, // record_len lo = 11 (enough to hold hs type byte)
                0x04, // hs_type: NewSessionTicket
            ]);

        assert!(tester.parse_new_session_ticket(&response).unwrap());
        assert!(
            !tester
                .parse_new_session_ticket(&[0x00, 0x01, 0x02])
                .unwrap()
        );
    }

    #[test]
    fn test_parse_new_session_ticket_inside_combined_record() {
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let response = handshake_record(&[
            handshake_message(0x0b, &[]),
            new_session_ticket_message(b"ticket"),
        ]);

        assert!(tester.parse_new_session_ticket(&response).unwrap());
    }

    #[test]
    fn test_extract_session_ticket_inside_combined_record() {
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let response = handshake_record(&[
            handshake_message(0x0b, &[]),
            new_session_ticket_message(b"ticket"),
        ]);

        assert_eq!(
            tester.extract_session_ticket(&response).unwrap().as_deref(),
            Some(&b"ticket"[..])
        );
    }

    fn ticketbleed_test_target() -> Target {
        Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap()
    }

    fn handshake_message(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![handshake_type, 0, 0, 0];
        message.extend_from_slice(body);
        write_u24_at(&mut message, 1, body.len());
        message
    }

    fn handshake_record(messages: &[Vec<u8>]) -> Vec<u8> {
        let body_len: usize = messages.iter().map(Vec::len).sum();
        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(body_len as u16).to_be_bytes());
        for message in messages {
            record.extend_from_slice(message);
        }
        record
    }

    fn new_session_ticket_message(ticket: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(ticket);
        handshake_message(0x04, &body)
    }

    /// Build a ServerHello TLS record echoing `session_id`.
    fn server_hello_record_with_session_id(session_id: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&[0xc0, 0x2f]); // cipher suite
        body.push(0x00); // compression method
        handshake_record(&[handshake_message(0x02, &body)])
    }

    #[test]
    fn test_detect_memory_leak_flags_padded_session_id_echo() {
        // Vulnerable F5: echoes a 32-byte Session ID that begins with our marker,
        // the trailing 16 bytes being leaked memory.
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let mut session_id = TICKETBLEED_SESSION_ID_MARKER.to_vec();
        session_id.extend_from_slice(&[0x77u8; 16]);
        let response = server_hello_record_with_session_id(&session_id);
        assert!(tester.detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_finds_serverhello_inside_combined_record() {
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let mut session_id = TICKETBLEED_SESSION_ID_MARKER.to_vec();
        session_id.extend_from_slice(&[0x77u8; 16]);

        let mut server_hello = Vec::new();
        server_hello.extend_from_slice(&[0x03, 0x03]);
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(session_id.len() as u8);
        server_hello.extend_from_slice(&session_id);
        server_hello.extend_from_slice(&[0xc0, 0x2f, 0x00]);

        let response = handshake_record(&[
            handshake_message(0x0b, &[]),
            handshake_message(0x02, &server_hello),
        ]);

        assert!(tester.detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_clears_exact_marker_echo() {
        // Healthy resumption: server echoes the marker at its exact length.
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let response = server_hello_record_with_session_id(&TICKETBLEED_SESSION_ID_MARKER);
        assert!(!tester.detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_clears_fresh_session_id() {
        // Fresh full handshake: a 32-byte Session ID not beginning with the marker.
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let fresh: Vec<u8> = (0..32u8).map(|i| 0x10 ^ i).collect();
        let response = server_hello_record_with_session_id(&fresh);
        assert!(!tester.detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_rejects_truncated_record() {
        // A record claiming more bytes than are present must not be parsed.
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let mut session_id = TICKETBLEED_SESSION_ID_MARKER.to_vec();
        session_id.extend_from_slice(&[0x77u8; 16]);
        let mut response = server_hello_record_with_session_id(&session_id);
        *response
            .get_mut(4)
            .expect("test response should contain record length byte") = 0xff; // inflate the record length past the buffer
        assert!(
            tester
                .detect_memory_leak(&response)
                .expect_err("truncated record should fail")
                .to_string()
                .contains("record length exceeds available data"),
            "a record longer than the buffer must be rejected"
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
        let err = tester
            .parse_new_session_ticket(&[0x16, 0x03])
            .expect_err("partial TLS record should fail");
        assert!(
            err.to_string()
                .contains("Ticketbleed TLS record header truncated")
        );
    }

    #[test]
    fn test_parse_new_session_ticket_rejects_truncated_handshake() {
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let response = [
            0x16, 0x03, 0x03, 0x00, 0x01, // record with one handshake byte
            0x04, // NewSessionTicket type, missing length
        ];

        let err = tester
            .parse_new_session_ticket(&response)
            .expect_err("truncated NewSessionTicket should fail");
        assert!(
            err.to_string()
                .contains("Ticketbleed NewSessionTicket header truncated")
        );
    }

    #[test]
    fn test_extract_session_ticket_rejects_truncated_ticket() {
        let tester = TicketbleedTester::new(ticketbleed_test_target());
        let mut response = vec![
            CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x20, // record length 32
            0x04,
            0x00,
            0x00,
            0x04, // NewSessionTicket handshake length 4
            0x00,
            0x00,
            0x00,
            0x01, // lifetime
            0x00,
            0x02, // bytes outside the declared handshake body
            0xaa,
            0xbb, // ticket bytes that should be ignored
        ];
        response.extend_from_slice(&[0xcc; 16]); // trailing record bytes

        let err = tester
            .extract_session_ticket(&response)
            .expect_err("truncated ticket should fail");
        let err = err.to_string();
        assert!(
            err.contains("Ticketbleed ticket length truncated")
                || err.contains("Ticketbleed ticket data exceeds handshake")
                || err.contains("Ticketbleed ticket TLS record length exceeds available data")
        );
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

    #[tokio::test]
    async fn test_ticketbleed_reads_past_first_record_for_new_session_ticket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.expect("read initial hello");

            socket
                .write_all(&handshake_record(&[handshake_message(0x0b, &[])]))
                .await
                .expect("write first response");
            tokio::time::sleep(Duration::from_millis(50)).await;
            socket
                .write_all(&handshake_record(&[new_session_ticket_message(b"ticket")]))
                .await
                .expect("write delayed ticket");

            let _ = socket.read(&mut buf).await.expect("read follow-up hello");
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let result = TicketbleedTester::new(target).test().await.unwrap();
        server.await.expect("server task");

        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "delayed NewSessionTicket must be consumed before the follow-up probe; got {result:?}"
        );
        assert!(result.details.contains("follow-up ClientHello"));
    }

    #[tokio::test]
    async fn test_ticketbleed_malformed_ticket_response_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.expect("read initial hello");

            let malformed_ticket = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x01, 0x04];
            socket
                .write_all(&malformed_ticket)
                .await
                .expect("write malformed ticket");
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let result = TicketbleedTester::new(target).test().await.unwrap();
        server.await.expect("server task");

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.details.contains("Malformed session ticket response"));
    }

    #[tokio::test]
    async fn test_ticketbleed_fragmented_new_session_ticket_is_reassembled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.expect("read initial hello");

            let ticket = handshake_record(&[new_session_ticket_message(b"ticket")]);
            let split = 6;
            socket
                .write_all(&ticket[..split])
                .await
                .expect("write first ticket chunk");
            tokio::time::sleep(Duration::from_millis(50)).await;
            socket
                .write_all(&ticket[split..])
                .await
                .expect("write second ticket chunk");

            let _ = socket.read(&mut buf).await.expect("read follow-up hello");
            socket
                .write_all(&server_hello_record_with_session_id(
                    &TICKETBLEED_SESSION_ID_MARKER,
                ))
                .await
                .expect("write follow-up server hello");
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let result = TicketbleedTester::new(target).test().await.unwrap();
        server.await.expect("server task");

        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
        assert!(result.details.contains("No memory leak detected"));
    }
}
