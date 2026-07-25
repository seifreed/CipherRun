// NPN (Next Protocol Negotiation) Testing
// NPN was the predecessor to ALPN (Application Layer Protocol Negotiation)
// It's now deprecated in favor of ALPN, but some servers still support it

use crate::Result;
use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_RECORD_HEADER_SIZE};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

mod server_hello;

/// NPN protocol tester
pub struct NpnTester {
    target: Target,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NpnProbeOutcome {
    Supported(Vec<String>),
    NotSupported,
    Inconclusive,
}

impl NpnTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    fn tls_record_total_len(
        header: &[u8; TLS_RECORD_HEADER_SIZE],
    ) -> std::io::Result<Option<usize>> {
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_SIZE
            .checked_add(record_len)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "NPN record length overflow",
                )
            })?;
        if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
            return Ok(None);
        }
        Ok(Some(total_len))
    }

    /// Test if NPN is supported
    pub async fn test(&self) -> Result<NpnTestResult> {
        let (supported_protocols, inconclusive) = match self.test_npn_support().await? {
            NpnProbeOutcome::Supported(protocols) => (protocols, false),
            NpnProbeOutcome::NotSupported => (Vec::new(), false),
            NpnProbeOutcome::Inconclusive => (Vec::new(), true),
        };
        let supported = !supported_protocols.is_empty();

        let details = if inconclusive {
            "NPN test inconclusive - no valid ServerHello received".to_string()
        } else if supported {
            format!(
                "NPN supported (deprecated) with {} protocol(s): {}",
                supported_protocols.len(),
                supported_protocols.join(", ")
            )
        } else {
            "NPN not supported (good - use ALPN instead)".to_string()
        };

        Ok(NpnTestResult {
            supported,
            protocols: supported_protocols,
            details,
            inconclusive,
        })
    }

    /// Test NPN support by sending ClientHello with NPN extension
    async fn test_npn_support(&self) -> Result<NpnProbeOutcome> {
        // Use raw TLS handshake to properly test NPN
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match crate::utils::network::connect_with_timeout(addr, Duration::from_secs(5), None).await
        {
            Ok(mut stream) => {
                // Send ClientHello with NPN extension
                let client_hello = self.build_client_hello_with_npn()?;
                stream.write_all(&client_hello).await?;

                // Read ServerHello as a complete TLS record before parsing.
                let response = match timeout(Duration::from_secs(3), async {
                    let mut header = [0u8; 5];
                    if stream.read_exact(&mut header).await.is_err() {
                        return Ok::<Option<Vec<u8>>, std::io::Error>(None);
                    }

                    let Some(total_len) = Self::tls_record_total_len(&header)? else {
                        return Ok::<Option<Vec<u8>>, std::io::Error>(None);
                    };
                    let mut buffer = vec![0u8; total_len];
                    buffer[..TLS_RECORD_HEADER_SIZE].copy_from_slice(&header);
                    if stream
                        .read_exact(&mut buffer[TLS_RECORD_HEADER_SIZE..])
                        .await
                        .is_err()
                    {
                        return Ok::<Option<Vec<u8>>, std::io::Error>(None);
                    }

                    Ok::<Option<Vec<u8>>, std::io::Error>(Some(buffer))
                })
                .await
                {
                    Ok(Ok(Some(resp))) => resp,
                    _ => return Ok(NpnProbeOutcome::Inconclusive),
                };

                if !server_hello::is_parseable(&response) {
                    return Ok(NpnProbeOutcome::Inconclusive);
                }
                let protocols = server_hello::parse_npn_protocols(&response)?;
                if protocols.is_empty() {
                    Ok(NpnProbeOutcome::NotSupported)
                } else {
                    Ok(NpnProbeOutcome::Supported(protocols))
                }
            }
            _ => Ok(NpnProbeOutcome::Inconclusive),
        }
    }

    /// Build ClientHello with NPN extension
    fn build_client_hello_with_npn(&self) -> Result<Vec<u8>> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(0x16);
        hello.push(0x03);
        hello.push(0x03); // TLS 1.2

        // Length placeholder
        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake: ClientHello
        hello.push(0x01);

        // Handshake length placeholder
        let hs_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client Version: TLS 1.2
        hello.push(0x03);
        hello.push(0x03);

        // Random (32 bytes)
        for i in 0_u8..32 {
            hello.push(i.wrapping_mul(7));
        }

        // Session ID (empty)
        hello.push(0x00);

        // Cipher Suites
        hello.push(0x00);
        hello.push(0x04);
        hello.push(0xc0);
        hello.push(0x2f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        hello.push(0x00);
        hello.push(0x9c); // TLS_RSA_WITH_AES_128_GCM_SHA256

        // Compression (none)
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let ext_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00); // Extensions length placeholder

        // NPN Extension (0x3374)
        hello.push(0x33);
        hello.push(0x74);
        hello.push(0x00);
        hello.push(0x00); // Empty NPN data

        // Update extensions length
        let ext_len = hello.len() - ext_pos - 2;
        if let Some(len_bytes) = hello.get_mut(ext_pos..ext_pos + 2) {
            len_bytes.copy_from_slice(&Self::u16_len(ext_len, "NPN extensions")?.to_be_bytes());
        }

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        if let Some(len_bytes) = hello.get_mut(hs_len_pos..hs_len_pos + 3) {
            len_bytes.copy_from_slice(&Self::u24_len(hs_len, "NPN handshake")?);
        }

        // Update record length
        let rec_len = hello.len() - len_pos - 2;
        if let Some(len_bytes) = hello.get_mut(len_pos..len_pos + 2) {
            len_bytes.copy_from_slice(&Self::u16_len(rec_len, "NPN record")?.to_be_bytes());
        }

        Ok(hello)
    }

    fn u16_len(len: usize, context: &str) -> Result<u16> {
        u16::try_from(len)
            .map_err(|_| crate::TlsError::Other(format!("{context} exceeds maximum length")))
    }

    fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
        let len = u32::try_from(len)
            .map_err(|_| crate::TlsError::Other(format!("{context} exceeds maximum length")))?;
        if len > 0x00ff_ffff {
            return Err(crate::TlsError::Other(format!(
                "{context} exceeds maximum length"
            )));
        }
        let bytes = len.to_be_bytes();
        Ok([bytes[1], bytes[2], bytes[3]])
    }
}

/// NPN test result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NpnTestResult {
    pub supported: bool,
    pub protocols: Vec<String>,
    pub details: String,
    #[serde(default)]
    pub inconclusive: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_npn_response(response: &[u8]) -> Result<Vec<String>> {
        server_hello::parse_npn_protocols(response)
    }

    #[test]
    fn test_npn_record_total_len_rejects_oversized_record() {
        let max_record_len = crate::constants::BUFFER_SIZE_MAX_WITH_OVERHEAD
            - crate::constants::TLS_RECORD_HEADER_SIZE;
        let allowed = max_record_len as u16;
        let rejected = (max_record_len + 1) as u16;

        let allowed_header = [0x16, 0x03, 0x03, (allowed >> 8) as u8, allowed as u8];
        assert_eq!(
            NpnTester::tls_record_total_len(&allowed_header).expect("length should parse"),
            Some(crate::constants::BUFFER_SIZE_MAX_WITH_OVERHEAD)
        );

        let rejected_header = [0x16, 0x03, 0x03, (rejected >> 8) as u8, rejected as u8];
        assert_eq!(
            NpnTester::tls_record_total_len(&rejected_header).expect("length should parse"),
            None
        );
    }

    #[test]
    fn test_npn_result() {
        let result = NpnTestResult {
            supported: false,
            protocols: vec![],
            details: "Test".to_string(),
            inconclusive: false,
        };
        assert!(!result.supported);
        assert!(result.protocols.is_empty());
    }

    #[test]
    fn test_npn_result_details_contains_text() {
        let result = NpnTestResult {
            supported: true,
            protocols: vec!["h2".to_string()],
            details: "NPN supported".to_string(),
            inconclusive: false,
        };
        assert!(result.details.contains("NPN"));
    }

    #[test]
    fn test_client_hello_with_npn() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = NpnTester::new(target);
        let hello = tester
            .build_client_hello_with_npn()
            .expect("NPN ClientHello should build");

        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello

        // Check for NPN extension (0x3374)
        let has_npn = hello.windows(2).any(|w| w == [0x33, 0x74]);
        assert!(has_npn);
    }

    #[test]
    fn test_parse_npn_response_with_protocols() {
        // Build a valid ServerHello with NPN extension
        let mut response = Vec::new();
        // TLS record header
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]); // type=handshake, version, length placeholder
        // Handshake header
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // type=ServerHello, length placeholder
        // Server version
        response.extend_from_slice(&[0x03, 0x03]);
        // Server random (32 bytes)
        response.extend_from_slice(&[0x00; 32]);
        // Session ID length: 0
        response.push(0x00);
        // Cipher suite
        response.extend_from_slice(&[0x00, 0x9c]);
        // Compression: none
        response.push(0x00);
        // Extensions length placeholder
        let ext_len_pos = response.len();
        response.extend_from_slice(&[0x00, 0x00]);
        // NPN extension (0x3374), data = protocol list
        response.extend_from_slice(&[0x33, 0x74, 0x00, 0x0c]); // ext type + len=12
        response.push(0x02);
        response.extend_from_slice(b"h2");
        response.push(0x08);
        response.extend_from_slice(b"http/1.1");

        // Patch lengths
        let ext_len = (response.len() - ext_len_pos - 2) as u16;
        response[ext_len_pos] = (ext_len >> 8) as u8;
        response[ext_len_pos + 1] = (ext_len & 0xff) as u8;
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        let protocols = parse_npn_response(&response).expect("test assertion should succeed");
        assert_eq!(protocols, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn test_parse_npn_response_rejects_invalid_protocol_utf8() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        let ext_len_pos = response.len();
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x33, 0x74, 0x00, 0x02]);
        response.extend_from_slice(&[0x01, 0xff]);

        let ext_len = (response.len() - ext_len_pos - 2) as u16;
        response[ext_len_pos] = (ext_len >> 8) as u8;
        response[ext_len_pos + 1] = (ext_len & 0xff) as u8;
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        let err = parse_npn_response(&response).expect_err("invalid protocol UTF-8 should fail");
        assert!(err.to_string().contains("Invalid NPN protocol name UTF-8"));
    }

    #[test]
    fn test_parse_npn_response_invalid_data() {
        // Not a valid ServerHello - should return empty
        let response = vec![0x33, 0x74, 0xff, 0xff];
        let protocols = parse_npn_response(&response).expect("test assertion should succeed");
        assert!(protocols.is_empty());
    }

    #[test]
    fn test_parse_npn_response_without_extension() {
        // Too short for a ServerHello
        let response = vec![0x01, 0x02, 0x03, 0x04];
        let protocols = parse_npn_response(&response).expect("test assertion should succeed");
        assert!(protocols.is_empty());
    }

    #[test]
    fn test_parse_npn_response_truncated() {
        // Truncated data - not a valid ServerHello
        let mut response = vec![0x16, 0x03, 0x03, 0x00, 0x02];
        response.push(0x03);
        response.push(b'h');

        let protocols = parse_npn_response(&response).expect("test assertion should succeed");
        assert!(protocols.is_empty());
    }

    #[test]
    fn test_parse_npn_response_rejects_truncated_extension_data() {
        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record header
            0x02, 0x00, 0x00, 0x00, // ServerHello header
            0x03, 0x03, // version
        ];
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00); // session id len
        response.extend_from_slice(&[0x00, 0x9c]); // cipher
        response.push(0x00); // compression
        response.extend_from_slice(&[0x00, 0x05]); // extensions len
        response.extend_from_slice(&[0x33, 0x74, 0x00, 0x02]); // NPN ext claims 2 bytes
        response.push(0x01); // truncated protocol list
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        let err = parse_npn_response(&response).expect_err("truncated NPN extension should fail");
        assert!(
            err.to_string()
                .contains("NPN extension data extends beyond declared length")
        );
    }

    #[test]
    fn test_parse_npn_response_rejects_truncated_extension_block() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        let ext_len_pos = response.len();
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x33, 0x74, 0x00, 0x0c]);
        response.push(0x02);
        response.extend_from_slice(b"h2");
        response.push(0x08);
        response.extend_from_slice(b"http/1.1");

        let ext_len = (response.len() - ext_len_pos - 2) as u16;
        let declared_ext_len = ext_len + 1;
        response[ext_len_pos] = (declared_ext_len >> 8) as u8;
        response[ext_len_pos + 1] = (declared_ext_len & 0xff) as u8;
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        let err = parse_npn_response(&response).expect_err("truncated extension block should fail");
        assert!(
            err.to_string()
                .contains("NPN extension block extends beyond handshake length")
        );
    }

    #[test]
    fn test_parse_npn_response_rejects_extension_block_trailing_bytes() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x00, 0xff]);
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        let err = parse_npn_response(&response).expect_err("trailing extension bytes should fail");
        assert!(
            err.to_string()
                .contains("NPN extension block contains trailing bytes")
        );
    }

    #[test]
    fn test_parse_npn_response_rejects_truncated_extension_header() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x03, 0x33, 0x74, 0x00]);
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        let err =
            parse_npn_response(&response).expect_err("truncated extension header should fail");
        assert!(
            err.to_string()
                .contains("NPN extension block contains truncated header")
        );
    }

    #[test]
    fn test_parse_npn_response_ignores_extension_after_handshake_end() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        response.extend_from_slice(&[0x00, 0x06, 0x33, 0x74, 0x00, 0x02, 0x01, b'h']);
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;

        let protocols =
            parse_npn_response(&response).expect("extension beyond ServerHello must be ignored");
        assert!(protocols.is_empty());
    }

    #[tokio::test]
    async fn test_npn_closed_target_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        drop(listener);

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = NpnTester::new(target);

        let result = tester.test().await.expect("NPN probe should return result");

        assert!(result.inconclusive);
        assert!(!result.supported);
        assert!(result.protocols.is_empty());
        assert!(result.details.contains("inconclusive"));
    }

    #[tokio::test]
    async fn test_npn_truncated_response_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(&[0x16, 0x03, 0x03, 0x00, 0x05]).await;
            }
        });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = NpnTester::new(target);

        let result = tester.test().await.expect("NPN probe should return result");

        assert!(result.inconclusive);
        assert!(!result.details.contains("not supported"));
    }

    #[tokio::test]
    async fn test_npn_fragmented_response_is_parsed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 1024];
                let _ = socket.read(&mut buffer).await;

                let mut response = Vec::new();
                response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
                response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
                response.extend_from_slice(&[0x03, 0x03]);
                response.extend_from_slice(&[0x00; 32]);
                response.push(0x00);
                response.extend_from_slice(&[0x00, 0x9c]);
                response.push(0x00);
                let ext_len_pos = response.len();
                response.extend_from_slice(&[0x00, 0x00]);
                response.extend_from_slice(&[0x33, 0x74, 0x00, 0x0c]);
                response.push(0x02);
                response.extend_from_slice(b"h2");
                response.push(0x08);
                response.extend_from_slice(b"http/1.1");

                let ext_len = (response.len() - ext_len_pos - 2) as u16;
                response[ext_len_pos] = (ext_len >> 8) as u8;
                response[ext_len_pos + 1] = (ext_len & 0xff) as u8;
                let hs_len = (response.len() - 9) as u32;
                response[6] = ((hs_len >> 16) & 0xff) as u8;
                response[7] = ((hs_len >> 8) & 0xff) as u8;
                response[8] = (hs_len & 0xff) as u8;
                let rec_len = (response.len() - 5) as u16;
                response[3] = (rec_len >> 8) as u8;
                response[4] = (rec_len & 0xff) as u8;

                socket.write_all(&response[..7]).await.unwrap();
                socket.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
                socket.write_all(&response[7..]).await.unwrap();
                socket.flush().await.unwrap();
            }
        });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = NpnTester::new(target);

        let result = tester.test().await.expect("NPN probe should return result");

        assert!(result.supported);
        assert!(!result.inconclusive);
        assert_eq!(
            result.protocols,
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }
}
