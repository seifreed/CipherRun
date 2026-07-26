// Heartbleed (CVE-2014-0160) vulnerability checker

use crate::Result;
use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_HANDSHAKE_TIMEOUT};
use crate::protocols::Protocol;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

mod client_hello;
mod heartbeat_probe;
mod heartbeat_response;
mod read_io;
mod result;
mod server_hello;

pub use result::HeartbleedResult;

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

        Ok(HeartbleedResult::aggregate_clean(any_tested))
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
                return Ok(HeartbleedResult::connection_failed());
            }
        };

        let client_hello = client_hello::with_heartbeat_extension(
            protocol,
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        )?;

        // Send ClientHello
        let response = match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;
            read_io::complete_tls_record(
                &mut stream,
                BUFFER_SIZE_MAX_WITH_OVERHEAD,
                self.read_timeout,
            )
            .await
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => {
                return Ok(HeartbleedResult::server_hello_timeout());
            }
        };

        if response.first() != Some(&0x16) || response.get(5) != Some(&0x02) {
            return Ok(HeartbleedResult::unexpected_server_hello(response.len()));
        }

        // Check if server accepted heartbeat extension
        match server_hello::has_heartbeat_extension(&response) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(HeartbleedResult::heartbeat_not_supported());
            }
            Err(error) => {
                return Ok(HeartbleedResult::malformed_server_hello(error));
            }
        }

        // Send malicious heartbeat request
        self.send_malicious_heartbeat(&mut stream).await
    }

    /// Send malicious heartbeat request and check for memory leak
    async fn send_malicious_heartbeat(&self, stream: &mut TcpStream) -> Result<HeartbleedResult> {
        let heartbeat = heartbeat_probe::malicious_request()?;
        stream.write_all(&heartbeat).await?;
        let result = match read_io::complete_tls_record(
            stream,
            u16::MAX as usize + crate::constants::TLS_RECORD_HEADER_SIZE,
            self.read_timeout,
        )
        .await
        {
            Ok(response) => response,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return Ok(HeartbleedResult::heartbeat_timeout(
                    heartbeat_probe::BYTES_SENT,
                ));
            }
            Err(_) => {
                return Ok(HeartbleedResult::heartbeat_connection_error(
                    heartbeat_probe::BYTES_SENT,
                ));
            }
        };

        Ok(heartbeat_probe::classify_response(&result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BUFFER_SIZE_MAX_TLS_RECORD, TLS_RECORD_HEADER_SIZE};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;
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
