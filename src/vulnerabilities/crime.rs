// CRIME (Compression Ratio Info-leak Made Easy) Vulnerability Test
// CVE-2012-4929
//
// CRIME exploits TLS/SSL compression to extract secrets (like session cookies)
// by observing changes in compression ratios when injecting known data.

use crate::Result;
use crate::constants::{
    BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_HANDSHAKE_TIMEOUT, TLS_RECORD_HEADER_SIZE,
};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

mod server_hello;

/// CRIME vulnerability tester
pub struct CrimeTester<'a> {
    target: &'a Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionProbeStatus {
    Enabled,
    Disabled,
    Inconclusive,
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

impl CompressionProbeStatus {
    fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }
}

impl<'a> CrimeTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before each CRIME probe.
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

    fn merge_probe_status(
        current: CompressionProbeStatus,
        next: CompressionProbeStatus,
    ) -> CompressionProbeStatus {
        match (current, next) {
            (CompressionProbeStatus::Enabled, _) | (_, CompressionProbeStatus::Enabled) => {
                CompressionProbeStatus::Enabled
            }
            (CompressionProbeStatus::Inconclusive, _)
            | (_, CompressionProbeStatus::Inconclusive) => CompressionProbeStatus::Inconclusive,
            _ => CompressionProbeStatus::Disabled,
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

    /// Test for CRIME vulnerability
    pub async fn test(&self) -> Result<CrimeTestResult> {
        let tls_compression = self.test_tls_compression().await?;
        let spdy_compression = self.test_spdy_compression().await?;

        let tls_compression_enabled = tls_compression.is_enabled();
        let spdy_compression_enabled = spdy_compression.is_enabled();
        let vulnerable = tls_compression_enabled || spdy_compression_enabled;
        let inconclusive = !vulnerable
            && (tls_compression.is_inconclusive() || spdy_compression.is_inconclusive());

        let details = if vulnerable {
            let mut parts = Vec::new();
            if tls_compression_enabled {
                parts.push("TLS compression enabled");
            }
            if spdy_compression_enabled {
                parts.push("SPDY compression enabled");
            }
            format!("Vulnerable to CRIME (CVE-2012-4929): {}", parts.join(", "))
        } else if inconclusive {
            "CRIME test inconclusive - unable to determine TLS/SPDY compression status".to_string()
        } else {
            "Not vulnerable - TLS/SPDY compression disabled".to_string()
        };

        Ok(CrimeTestResult {
            vulnerable,
            inconclusive,
            tls_compression_enabled,
            spdy_compression_enabled,
            details,
        })
    }

    /// Test if TLS compression is enabled
    ///
    /// Checks whether TLS-level compression (DEFLATE) was negotiated.
    /// Modern OpenSSL disables compression by default due to CRIME vulnerability.
    /// This test attempts to negotiate compression and checks if it was enabled.
    async fn test_tls_compression(&self) -> Result<CompressionProbeStatus> {
        let mut status = CompressionProbeStatus::Disabled;
        for addr in self.probe_addrs()? {
            status = Self::merge_probe_status(status, self.test_tls_compression_addr(addr).await?);
            if status == CompressionProbeStatus::Enabled {
                break;
            }
        }
        Ok(status)
    }

    async fn test_tls_compression_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<CompressionProbeStatus> {
        // Modern OpenSSL (1.1.0+) disables compression by default.
        // OpenSSL 3.x removes it entirely. Most servers will have compression disabled.
        //
        // For legacy systems, we attempt to detect compression via the handshake.
        // We send a ClientHello offering DEFLATE compression and check if the
        // server accepts it by looking at the compression method in ServerHello.

        let mut stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return Ok(CompressionProbeStatus::Inconclusive),
        };

        // Send ClientHello with compression method DEFLATE (0x01)
        let client_hello = self.build_client_hello_with_compression()?;
        stream.write_all(&client_hello).await?;

        // Read the full ServerHello record so a fragmented response is not
        // misclassified as inconclusive.
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        match timeout(
            Duration::from_secs(3),
            Self::read_complete_tls_record(&mut stream, &mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 11 => {
                let Some(response) = buffer.get(..n) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                Ok(server_hello::tls_compression_status(response))
            }
            _ => Ok(CompressionProbeStatus::Inconclusive),
        }
    }

    /// Build ClientHello offering DEFLATE compression
    fn build_client_hello_with_compression(&self) -> Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_rsa_key_exchange().with_compression(true);
        builder.build()
    }

    /// Test if SPDY compression is enabled
    ///
    /// SPDY uses header compression (DEFLATE-based) which is vulnerable to CRIME.
    /// HTTP/2 uses HPACK which is specifically designed to resist CRIME-style attacks,
    /// so HTTP/2 is NOT flagged as vulnerable.
    ///
    /// Detection approach: Parse the ServerHello extensions to find NPN (0x3374),
    /// then check if any negotiated protocol is SPDY (not h2/HTTP2).
    async fn test_spdy_compression(&self) -> Result<CompressionProbeStatus> {
        let mut status = CompressionProbeStatus::Disabled;
        for addr in self.probe_addrs()? {
            status = Self::merge_probe_status(status, self.test_spdy_compression_addr(addr).await?);
            if status == CompressionProbeStatus::Enabled {
                break;
            }
        }
        Ok(status)
    }

    async fn test_spdy_compression_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<CompressionProbeStatus> {
        let mut stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return Ok(CompressionProbeStatus::Inconclusive),
        };

        // Send ClientHello with NPN extension advertising SPDY support
        let client_hello = self.build_client_hello_with_npn()?;
        stream.write_all(&client_hello).await?;

        // Read the full ServerHello record so a fragmented response is not
        // misclassified as inconclusive.
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        match timeout(
            Duration::from_secs(3),
            Self::read_complete_tls_record(&mut stream, &mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 43 => {
                let Some(data) = buffer.get(..n) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                Ok(server_hello::spdy_compression_status(data))
            }
            _ => Ok(CompressionProbeStatus::Inconclusive),
        }
    }

    /// Build ClientHello with NPN extension for SPDY using ClientHelloBuilder
    fn build_client_hello_with_npn(&self) -> Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder
            .for_rsa_key_exchange()
            .with_compression(true) // Enable DEFLATE for CRIME testing
            .add_npn(); // Add NPN extension for SPDY
        builder.build()
    }

    async fn read_complete_tls_record(
        stream: &mut tokio::net::TcpStream,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        use std::io::ErrorKind;
        use tokio::time::timeout;

        let mut total = 0;
        while total < buffer.len() {
            match timeout(Duration::from_secs(3), stream.read(&mut buffer[total..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    total += n;
                    if total >= TLS_RECORD_HEADER_SIZE {
                        let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
                        let record_total = TLS_RECORD_HEADER_SIZE
                            .checked_add(record_len)
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    "CRIME TLS record length overflow",
                                )
                            })?;
                        if record_total > buffer.len() {
                            return Err(std::io::Error::new(
                                ErrorKind::InvalidData,
                                "CRIME TLS record length exceeds buffer",
                            ));
                        }
                        if total >= record_total {
                            break;
                        }
                    }
                }
                Ok(Err(err))
                    if total == 0
                        && matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    return Ok(0);
                }
                Ok(Err(err))
                    if total > 0
                        && matches!(
                            err.kind(),
                            ErrorKind::TimedOut
                                | ErrorKind::WouldBlock
                                | ErrorKind::UnexpectedEof
                                | ErrorKind::ConnectionReset
                        ) =>
                {
                    break;
                }
                Ok(Err(err)) => return Err(err),
                Err(_) if total > 0 => break,
                Err(_) => return Ok(0),
            }
        }

        Ok(total)
    }
}

/// CRIME test result
#[derive(Debug, Clone)]
pub struct CrimeTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub tls_compression_enabled: bool,
    pub spdy_compression_enabled: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BUFFER_SIZE_DEFAULT, CONTENT_TYPE_HANDSHAKE};
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use tokio::io::AsyncWriteExt;
    use tokio::time::{Duration, sleep};

    #[test]
    fn test_crime_probe_addrs_honors_all_ips() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let single = CrimeTester::new(&target).probe_addrs().unwrap();
        let all = CrimeTester::new(&target)
            .with_test_all_ips(true)
            .probe_addrs()
            .unwrap();

        assert_eq!(single.len(), 1);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_crime_merge_keeps_inconclusive_over_disabled() {
        assert_eq!(
            CrimeTester::merge_probe_status(
                CompressionProbeStatus::Disabled,
                CompressionProbeStatus::Inconclusive,
            ),
            CompressionProbeStatus::Inconclusive
        );
    }

    #[tokio::test]
    async fn test_read_complete_tls_record_accepts_record_above_default_buffer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept should succeed");
            let record_len = BUFFER_SIZE_DEFAULT as u16;
            let header = [
                CONTENT_TYPE_HANDSHAKE,
                0x03,
                0x03,
                (record_len >> 8) as u8,
                record_len as u8,
            ];
            socket.write_all(&header).await.expect("write header");
            socket
                .write_all(&vec![0u8; BUFFER_SIZE_DEFAULT])
                .await
                .expect("write body");
        });

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect should succeed");
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        let n = CrimeTester::read_complete_tls_record(&mut stream, &mut buffer)
            .await
            .expect("record should read");

        assert_eq!(n, 5 + BUFFER_SIZE_DEFAULT);
        server.await.expect("server should finish");
    }

    #[tokio::test]
    async fn test_read_complete_tls_record_rejects_oversized_record_for_buffer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept should succeed");
            socket
                .write_all(&[CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x20])
                .await
                .expect("write header");
            socket.write_all(&[0u8; 8]).await.expect("write body");
        });

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect should succeed");
        let mut buffer = [0u8; 16];
        let err = CrimeTester::read_complete_tls_record(&mut stream, &mut buffer)
            .await
            .expect_err("oversized record should fail");

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        server.await.expect("server should finish");
    }

    #[test]
    fn test_crime_result_creation() {
        let result = CrimeTestResult {
            vulnerable: true,
            inconclusive: false,
            tls_compression_enabled: true,
            spdy_compression_enabled: false,
            details: "Test".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.tls_compression_enabled);
        assert!(!result.spdy_compression_enabled);
    }

    #[test]
    fn test_client_hello_with_npn() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let hello = tester
            .build_client_hello_with_npn()
            .expect("ClientHello should build");

        assert!(hello.len() > 50);
        assert_eq!(hello.first(), Some(&0x16)); // Handshake
        assert_eq!(hello.get(5), Some(&0x01)); // ClientHello

        // Check for compression methods (DEFLATE = 0x01)
        let has_deflate = hello.windows(2).any(|w| w == [0x02, 0x01]);
        assert!(has_deflate);
    }

    #[test]
    fn test_crime_result_debug_contains_details() {
        let result = CrimeTestResult {
            vulnerable: false,
            inconclusive: false,
            tls_compression_enabled: false,
            spdy_compression_enabled: false,
            details: "No compression".to_string(),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("No compression"));
    }

    #[test]
    fn test_crime_result_not_vulnerable_text() {
        let result = CrimeTestResult {
            vulnerable: false,
            inconclusive: false,
            tls_compression_enabled: false,
            spdy_compression_enabled: false,
            details: "Not vulnerable - TLS/SPDY compression disabled".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_client_hello_with_npn_contains_extension_id() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let hello = tester
            .build_client_hello_with_npn()
            .expect("ClientHello should build");

        // NPN extension type is 0x3374
        assert!(hello.windows(2).any(|w| w == [0x33, 0x74]));
    }

    #[tokio::test]
    async fn test_spdy_probe_rejects_truncated_npn_extension() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let mut response = vec![
                0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
            ];
            response.extend_from_slice(&[0xAA; 32]);
            response.push(0x00);
            response.extend_from_slice(&[0x00, 0x9c]);
            response.push(0x00);
            response.extend_from_slice(&[0x00, 0x06]); // claims 6 bytes of extensions
            response.extend_from_slice(&[0x33, 0x74, 0x00, 0x02]); // NPN ext header
            response.push(0x01); // truncated protocol list

            let rec_len = (response.len() - 5) as u16;
            write_u16_at(&mut response, 3, rec_len);
            let hs_len = response.len() - 9;
            write_u24_at(&mut response, 6, hs_len);

            socket.write_all(&response).await.unwrap();
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = CrimeTester::new(&target);

        let status = tester
            .test_spdy_compression()
            .await
            .expect("probe should return a status");
        assert_eq!(status, CompressionProbeStatus::Inconclusive);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_spdy_probe_rejects_trailing_extension_after_spdy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let mut response = vec![
                0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
            ];
            response.extend_from_slice(&[0xAA; 32]);
            response.push(0x00);
            response.extend_from_slice(&[0x00, 0x9c]);
            response.push(0x00);
            response.extend_from_slice(&[0x00, 0x00]);
            let ext_len_pos = response.len() - 2;
            response.extend_from_slice(&[0x33, 0x74, 0x00, 0x07]);
            response.push(0x06);
            response.extend_from_slice(b"spdy/3");
            response.push(0xff); // trailing partial extension header

            let ext_len = (response.len() - ext_len_pos - 2) as u16;
            write_u16_at(&mut response, ext_len_pos, ext_len);
            let rec_len = (response.len() - 5) as u16;
            write_u16_at(&mut response, 3, rec_len);
            let hs_len = response.len() - 9;
            write_u24_at(&mut response, 6, hs_len);

            socket.write_all(&response).await.unwrap();
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = CrimeTester::new(&target);

        let status = tester
            .test_spdy_compression()
            .await
            .expect("probe should return a status");
        assert_eq!(status, CompressionProbeStatus::Inconclusive);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_spdy_probe_detects_npn_in_combined_handshake_record() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let mut response = vec![
                0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
            ];
            response.extend_from_slice(&[0xAA; 32]);
            response.push(0x00);
            response.extend_from_slice(&[0x00, 0x9c]);
            response.push(0x00);
            response.extend_from_slice(&[0x00, 0x00]);
            let ext_len_pos = response.len() - 2;
            response.extend_from_slice(&[0x33, 0x74, 0x00, 0x07]);
            response.push(0x06);
            response.extend_from_slice(b"spdy/3");

            let ext_len = (response.len() - ext_len_pos - 2) as u16;
            write_u16_at(&mut response, ext_len_pos, ext_len);
            let hs_len = response.len() - 9;
            write_u24_at(&mut response, 6, hs_len);

            response.extend_from_slice(&[0x0b, 0x00, 0x00, 0x00]);
            let rec_len = (response.len() - 5) as u16;
            write_u16_at(&mut response, 3, rec_len);

            socket.write_all(&response).await.unwrap();
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = CrimeTester::new(&target);

        let status = tester
            .test_spdy_compression()
            .await
            .expect("probe should return a status");
        assert_eq!(status, CompressionProbeStatus::Enabled);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_compression_reads_fragmented_server_hello_record() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let mut response = vec![
                0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
            ];
            response.extend_from_slice(&[0xAA; 32]);
            response.push(0x00);
            response.extend_from_slice(&[0x00, 0x9c]);
            response.push(0x01);
            response.extend_from_slice(&[0x00, 0x00]);

            let rec_len = (response.len() - 5) as u16;
            write_u16_at(&mut response, 3, rec_len);
            let hs_len = response.len() - 9;
            write_u24_at(&mut response, 6, hs_len);

            let split = response.len() / 2;
            let _ = socket.write_all(&response[..split]).await;
            sleep(Duration::from_millis(50)).await;
            let _ = socket.write_all(&response[split..]).await;
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = CrimeTester::new(&target);

        let status = tester
            .test_tls_compression()
            .await
            .expect("probe should return a status");
        assert_eq!(status, CompressionProbeStatus::Enabled);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_compression_truncated_server_hello_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let mut response = vec![
                0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
            ];
            response.extend_from_slice(&[0xAA; 32]);

            let rec_len = (response.len() - 5) as u16;
            write_u16_at(&mut response, 3, rec_len);
            let hs_len = response.len() - 9;
            write_u24_at(&mut response, 6, hs_len);

            socket.write_all(&response).await.unwrap();
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = CrimeTester::new(&target);

        let status = tester
            .test_tls_compression()
            .await
            .expect("probe should return a status");
        assert_eq!(status, CompressionProbeStatus::Inconclusive);

        server.await.unwrap();
    }

    #[test]
    fn test_client_hello_with_compression() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let hello = tester
            .build_client_hello_with_compression()
            .expect("ClientHello should build");

        assert!(hello.len() > 50);
        assert_eq!(hello.first(), Some(&0x16)); // Handshake
        assert_eq!(hello.get(5), Some(&0x01)); // ClientHello

        // Check for compression methods (should include DEFLATE = 0x01)
        let has_deflate = hello.windows(2).any(|w| w == [0x02, 0x01]);
        assert!(has_deflate, "ClientHello should offer DEFLATE compression");
    }

    #[tokio::test]
    async fn test_crime_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(!result.tls_compression_enabled);
        assert!(!result.spdy_compression_enabled);
        assert!(
            result.details.to_ascii_lowercase().contains("inconclusive"),
            "inactive target must not be reported as a clean CRIME pass: {}",
            result.details
        );
    }
}
