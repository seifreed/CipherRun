// Ticketbleed Vulnerability Test
// CVE-2016-9244
//
// Ticketbleed is a vulnerability in F5 BIG-IP that leaks 31 bytes of uninitialized memory
// when processing TLS session tickets. This can expose sensitive information including
// session keys, passwords, and other confidential data.

use crate::Result;
use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_HANDSHAKE_TIMEOUT};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

mod client_hello;
mod outcome;
mod read_io;
mod server_hello;
mod session_ticket;

use outcome::TicketbleedProbeOutcome;
pub use outcome::TicketbleedTestResult;

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
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

impl TicketbleedTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before the Ticketbleed probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
        server_mode: bool,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self.starttls_server_mode = server_mode;
        self
    }

    pub fn with_test_all_ips(mut self, test_all_ips: bool) -> Self {
        self.test_all_ips = test_all_ips;
        self
    }

    fn probe_addrs(&self) -> Result<Vec<std::net::SocketAddr>> {
        let addrs: Vec<_> = if self.test_all_ips {
            self.target.socket_addrs()
        } else {
            self.target
                .socket_addrs()
                .first()
                .copied()
                .into_iter()
                .collect()
        };
        if addrs.is_empty() {
            Err(crate::TlsError::NoSocketAddresses)
        } else {
            Ok(addrs)
        }
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
        crate::utils::network::connect_with_starttls(
            addr,
            timeout,
            self.starttls,
            &hostname,
            self.starttls_server_mode,
        )
        .await
    }

    /// Test for Ticketbleed vulnerability
    pub async fn test(&self) -> Result<TicketbleedTestResult> {
        Ok(self.test_session_ticket_leak().await?.into_test_result())
    }

    /// Test for session ticket memory leak
    async fn test_session_ticket_leak(&self) -> Result<TicketbleedProbeOutcome> {
        let mut outcome: Option<TicketbleedProbeOutcome> = None;
        for addr in self.probe_addrs()? {
            let next = self.test_session_ticket_leak_addr(addr).await?;
            outcome = Some(match outcome {
                Some(current) => current.merge(next),
                None => next,
            });
            if matches!(outcome, Some(TicketbleedProbeOutcome::Vulnerable)) {
                break;
            }
        }

        outcome.ok_or(crate::TlsError::NoSocketAddresses)
    }

    async fn test_session_ticket_leak_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<TicketbleedProbeOutcome> {
        match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(mut stream) => {
                let client_hello = client_hello::with_empty_session_ticket()?;
                stream.write_all(&client_hello).await?;

                let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
                let n = read_io::until_new_session_ticket(
                    &mut stream,
                    &mut buffer,
                    Duration::from_secs(3),
                )
                .await;
                match n {
                    n if n > 0 => {
                        let server_response =
                            buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                                message: "Ticketbleed ticket response read length exceeded buffer"
                                    .to_string(),
                            })?;
                        let has_new_ticket = match session_ticket::is_present(server_response) {
                            Ok(value) => value,
                            Err(_) => {
                                return Ok(TicketbleedProbeOutcome::Inconclusive(
                                    "Malformed session ticket response",
                                ));
                            }
                        };

                        if has_new_ticket {
                            let client_hello2 = match client_hello::with_received_ticket(
                                server_response,
                                session_ticket::extract,
                            ) {
                                Ok(value) => value,
                                Err(_) => {
                                    return Ok(TicketbleedProbeOutcome::Inconclusive(
                                        "Malformed session ticket response",
                                    ));
                                }
                            };
                            stream.write_all(&client_hello2).await?;

                            let mut response = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
                            match read_io::complete_tls_record(
                                &mut stream,
                                &mut response,
                                Duration::from_secs(3),
                            )
                            .await
                            {
                                Ok(m) if m > 0 => {
                                    let resumed_response = response.get(..m).ok_or_else(|| {
                                        crate::TlsError::ParseError {
                                            message:
                                                "Ticketbleed resumed response read length exceeded buffer"
                                                    .to_string(),
                                        }
                                    })?;
                                    let leaked =
                                        server_hello::detect_memory_leak(resumed_response)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BUFFER_SIZE_MAX_TLS_RECORD, CONTENT_TYPE_HANDSHAKE};
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
    fn test_ticketbleed_probe_addrs_honors_all_ips() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let single = TicketbleedTester::new(target.clone())
            .probe_addrs()
            .unwrap();
        let all = TicketbleedTester::new(target)
            .with_test_all_ips(true)
            .probe_addrs()
            .unwrap();

        assert_eq!(single.len(), 1);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_ticketbleed_merge_keeps_inconclusive_over_clean() {
        let merged = TicketbleedProbeOutcome::NotVulnerable("clean")
            .merge(TicketbleedProbeOutcome::Inconclusive("timeout"));

        assert!(matches!(
            merged,
            TicketbleedProbeOutcome::Inconclusive("timeout")
        ));
    }

    #[test]
    fn test_client_hello_with_session_ticket() {
        let hello = client_hello::with_empty_session_ticket().expect("ClientHello should build");

        assert!(hello.len() > 50);
        assert_eq!(hello.first(), Some(&0x16)); // Handshake
        assert_eq!(hello.get(5), Some(&0x01)); // ClientHello

        // Check for SessionTicket extension (0x0023)
        let has_ticket_ext = hello.windows(2).any(|w| w == [0x00, 0x23]);
        assert!(has_ticket_ext);
    }

    #[test]
    fn test_parse_new_session_ticket_detection() {
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

        assert!(session_ticket::is_present(&response).unwrap());
        assert!(session_ticket::is_present(&[0x00, 0x01, 0x02]).is_err());
    }

    #[test]
    fn test_parse_new_session_ticket_inside_combined_record() {
        let response = handshake_record(&[
            handshake_message(0x0b, &[]),
            new_session_ticket_message(b"ticket"),
        ]);

        assert!(session_ticket::is_present(&response).unwrap());
    }

    #[test]
    fn test_extract_session_ticket_inside_combined_record() {
        let response = handshake_record(&[
            handshake_message(0x0b, &[]),
            new_session_ticket_message(b"ticket"),
        ]);

        assert_eq!(
            session_ticket::extract(&response).unwrap().as_deref(),
            Some(&b"ticket"[..])
        );
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
        let mut session_id = client_hello::SESSION_ID_MARKER.to_vec();
        session_id.extend_from_slice(&[0x77u8; 16]);
        let response = server_hello_record_with_session_id(&session_id);
        assert!(server_hello::detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_finds_serverhello_inside_combined_record() {
        let mut session_id = client_hello::SESSION_ID_MARKER.to_vec();
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

        assert!(server_hello::detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_clears_exact_marker_echo() {
        // Healthy resumption: server echoes the marker at its exact length.
        let response = server_hello_record_with_session_id(&client_hello::SESSION_ID_MARKER);
        assert!(!server_hello::detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_clears_fresh_session_id() {
        // Fresh full handshake: a 32-byte Session ID not beginning with the marker.
        let fresh: Vec<u8> = (0..32u8).map(|i| 0x10 ^ i).collect();
        let response = server_hello_record_with_session_id(&fresh);
        assert!(!server_hello::detect_memory_leak(&response).unwrap());
    }

    #[test]
    fn test_detect_memory_leak_rejects_truncated_record() {
        // A record claiming more bytes than are present must not be parsed.
        let mut session_id = client_hello::SESSION_ID_MARKER.to_vec();
        session_id.extend_from_slice(&[0x77u8; 16]);
        let mut response = server_hello_record_with_session_id(&session_id);
        *response
            .get_mut(4)
            .expect("test response should contain record length byte") = 0xff; // inflate the record length past the buffer
        assert!(
            server_hello::detect_memory_leak(&response)
                .expect_err("truncated record should fail")
                .to_string()
                .contains("record length exceeds available data"),
            "a record longer than the buffer must be rejected"
        );
    }

    #[test]
    fn test_parse_new_session_ticket_short_response() {
        let err =
            session_ticket::is_present(&[0x16, 0x03]).expect_err("partial TLS record should fail");
        assert!(
            err.to_string()
                .contains("Ticketbleed TLS record header truncated")
        );
    }

    #[test]
    fn test_parse_new_session_ticket_rejects_truncated_handshake() {
        let response = [
            0x16, 0x03, 0x03, 0x00, 0x01, // record with one handshake byte
            0x04, // NewSessionTicket type, missing length
        ];

        let err = session_ticket::is_present(&response)
            .expect_err("truncated NewSessionTicket should fail");
        assert!(
            err.to_string()
                .contains("Ticketbleed NewSessionTicket header truncated")
        );
    }

    #[test]
    fn test_extract_session_ticket_rejects_truncated_ticket() {
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

        let err = session_ticket::extract(&response).expect_err("truncated ticket should fail");
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
    async fn test_ticketbleed_reads_past_max_size_record_for_new_session_ticket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.expect("read initial hello");

            let max_record_payload = vec![0u8; BUFFER_SIZE_MAX_TLS_RECORD - 4];
            socket
                .write_all(&handshake_record(&[handshake_message(
                    0x0b,
                    &max_record_payload,
                )]))
                .await
                .expect("write max-size response");
            socket
                .write_all(&handshake_record(&[new_session_ticket_message(b"ticket")]))
                .await
                .expect("write ticket response");

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
            "max-size TLS record before NewSessionTicket must not truncate ticket probe; got {result:?}"
        );
        assert!(result.details.contains("follow-up ClientHello"));
    }

    #[tokio::test]
    async fn test_ticketbleed_reads_split_resumed_response_record() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.expect("read request");

            let response = handshake_record(&[server_hello_record_with_session_id(
                &client_hello::SESSION_ID_MARKER,
            )]);
            socket
                .write_all(&response[..4])
                .await
                .expect("write first chunk");
            tokio::time::sleep(Duration::from_millis(50)).await;
            socket
                .write_all(&response[4..])
                .await
                .expect("write second chunk");
        });

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        stream.write_all(b"hello").await.expect("write request");
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        let n = read_io::complete_tls_record(&mut stream, &mut buffer, Duration::from_secs(2))
            .await
            .expect("record should read");
        assert!(n >= 5);

        server.await.expect("server task");
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
                    &client_hello::SESSION_ID_MARKER,
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
