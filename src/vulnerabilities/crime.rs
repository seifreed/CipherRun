// CRIME (Compression Ratio Info-leak Made Easy) Vulnerability Test
// CVE-2012-4929
//
// CRIME exploits TLS/SSL compression to extract secrets (like session cookies)
// by observing changes in compression ratios when injecting known data.

use crate::Result;
use crate::constants::{
    BUFFER_SIZE_MAX_WITH_OVERHEAD, CONTENT_TYPE_HANDSHAKE, TLS_HANDSHAKE_TIMEOUT,
    TLS_RECORD_HEADER_SIZE,
};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// CRIME vulnerability tester
pub struct CrimeTester<'a> {
    target: &'a Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionProbeStatus {
    Enabled,
    Disabled,
    Inconclusive,
}

fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

fn read_u24_at(data: &[u8], offset: usize) -> Option<usize> {
    let bytes = data.get(offset..offset.checked_add(3)?)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

fn slice_range(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    data.get(start..start.checked_add(len)?)
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
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before each CRIME probe.
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
        // Modern OpenSSL (1.1.0+) disables compression by default.
        // OpenSSL 3.x removes it entirely. Most servers will have compression disabled.
        //
        // For legacy systems, we attempt to detect compression via the handshake.
        // We send a ClientHello offering DEFLATE compression and check if the
        // server accepts it by looking at the compression method in ServerHello.

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

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
                // Validate the TLS record length so we only parse within the first record
                let Some(record_len) = read_u16_at(response, 3).map(usize::from) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                if record_len + 5 > n {
                    // Truncated ServerHello split across reads; the probe cannot decide.
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                if response.first() == Some(&CONTENT_TYPE_HANDSHAKE)
                    && response.get(5) == Some(&0x02)
                {
                    if n <= 43 {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    }
                    let Some(session_id_len) = response.get(43).copied().map(usize::from) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    if session_id_len > 32 {
                        // Malformed ServerHello — cannot determine compression status
                        return Ok(CompressionProbeStatus::Inconclusive);
                    }
                    let Some(cipher_offset) = 44usize.checked_add(session_id_len) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    // Ensure cipher_offset is within the first TLS record body (5+record_len)
                    let Some(compression_offset) = cipher_offset.checked_add(2) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    let Some(record_end) = 5usize.checked_add(record_len) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    if compression_offset < record_end && n > compression_offset {
                        let Some(compression_method) = response.get(compression_offset).copied()
                        else {
                            return Ok(CompressionProbeStatus::Inconclusive);
                        };
                        tracing::debug!("Server compression method: {}", compression_method);
                        return Ok(if compression_method == 0x01 {
                            CompressionProbeStatus::Enabled
                        } else {
                            CompressionProbeStatus::Disabled
                        });
                    }
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                Ok(CompressionProbeStatus::Disabled)
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
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

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
                // Parse ServerHello structurally to find NPN extension
                let Some(data) = buffer.get(..n) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };

                // Verify it's a handshake ServerHello
                if data.len() < 6 || data.first() != Some(&0x16) || data.get(5) != Some(&0x02) {
                    return Ok(CompressionProbeStatus::Disabled);
                }

                // Parse to extensions: skip record header (5) + handshake header (4)
                // + version (2) + random (32) + session_id
                let sid_offset = 43;
                if sid_offset >= n {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                let Some(sid_len) = data.get(sid_offset).copied().map(usize::from) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                // cipher suite (2) + compression (1) + extensions_length (2)
                let Some(ext_len_offset) = sid_offset
                    .checked_add(1)
                    .and_then(|offset| offset.checked_add(sid_len))
                    .and_then(|offset| offset.checked_add(2 + 1))
                else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                let Some(ext_start) = ext_len_offset.checked_add(2) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                if ext_start > n {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }

                // Validate TLS record length before parsing extensions
                let Some(record_len) = read_u16_at(data, 3).map(usize::from) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                let Some(record_end) = 5usize.checked_add(record_len) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                if record_end > n {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                let Some(hs_len) = read_u24_at(data, 6) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                let Some(hs_end) = 9usize.checked_add(hs_len) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                if hs_end > record_end {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                if ext_len_offset == hs_end {
                    return Ok(CompressionProbeStatus::Disabled);
                }
                if ext_start > hs_end {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }

                let Some(ext_total) = read_u16_at(data, ext_len_offset).map(usize::from) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                let Some(ext_end) = ext_start.checked_add(ext_total) else {
                    return Ok(CompressionProbeStatus::Inconclusive);
                };
                if ext_end > hs_end {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                if ext_end != hs_end {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }

                // Walk extensions structurally looking for NPN (0x3374)
                let mut pos = ext_start;
                let mut spdy_detected = false;
                while let Some(ext_header_end) = pos.checked_add(4).filter(|&end| end <= ext_end) {
                    let Some(ext_type) = read_u16_at(data, pos) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    let Some(ext_len_offset) = pos.checked_add(2) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    let Some(ext_len) = read_u16_at(data, ext_len_offset).map(usize::from) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    pos = ext_header_end;
                    let Some(next_pos) = pos.checked_add(ext_len) else {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    };
                    if next_pos > ext_end {
                        return Ok(CompressionProbeStatus::Inconclusive);
                    }

                    if ext_type == 0x3374 {
                        // Parse NPN protocol list within this extension
                        let mut proto_pos = pos;
                        let proto_end = next_pos;
                        while proto_pos < proto_end {
                            let Some(proto_len) = data.get(proto_pos).copied().map(usize::from)
                            else {
                                return Ok(CompressionProbeStatus::Inconclusive);
                            };
                            let Some(proto_start) = proto_pos.checked_add(1) else {
                                return Ok(CompressionProbeStatus::Inconclusive);
                            };
                            proto_pos = proto_start;
                            let Some(next_proto_pos) = proto_pos.checked_add(proto_len) else {
                                return Ok(CompressionProbeStatus::Inconclusive);
                            };
                            if next_proto_pos > proto_end {
                                return Ok(CompressionProbeStatus::Inconclusive);
                            }
                            if let Some(proto_bytes) = slice_range(data, proto_pos, proto_len)
                                && let Ok(proto) = std::str::from_utf8(proto_bytes)
                            {
                                // Only flag SPDY protocols as CRIME-vulnerable
                                // HTTP/2 (h2, h2c) uses HPACK which is CRIME-resistant
                                if proto.starts_with("spdy/") {
                                    spdy_detected = true;
                                }
                            }
                            proto_pos = next_proto_pos;
                        }
                    }

                    pos = next_pos;
                }
                if pos != ext_end {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }

                Ok(if spdy_detected {
                    CompressionProbeStatus::Enabled
                } else {
                    CompressionProbeStatus::Disabled
                })
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
    use crate::constants::BUFFER_SIZE_DEFAULT;
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use tokio::io::AsyncWriteExt;
    use tokio::time::{Duration, sleep};

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
