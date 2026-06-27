// NPN (Next Protocol Negotiation) Testing
// NPN was the predecessor to ALPN (Application Layer Protocol Negotiation)
// It's now deprecated in favor of ALPN, but some servers still support it

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

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

    fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
        data.get(offset)
            .copied()
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })
    }

    fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
        let end = offset
            .checked_add(2)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        let bytes = data
            .get(offset..end)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn slice_range<'a>(
        data: &'a [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> Result<&'a [u8]> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        data.get(start..end)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })
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

                // Read ServerHello
                let mut buffer = vec![0u8; 8192];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = Self::slice_range(&buffer, 0, n, "NPN response buffer")?;
                        if !Self::is_parseable_server_hello(response) {
                            return Ok(NpnProbeOutcome::Inconclusive);
                        }
                        // Parse ServerHello for NPN extension
                        let protocols = self.parse_npn_response(response)?;
                        if protocols.is_empty() {
                            Ok(NpnProbeOutcome::NotSupported)
                        } else {
                            Ok(NpnProbeOutcome::Supported(protocols))
                        }
                    }
                    _ => Ok(NpnProbeOutcome::Inconclusive),
                }
            }
            _ => Ok(NpnProbeOutcome::Inconclusive),
        }
    }

    fn is_parseable_server_hello(response: &[u8]) -> bool {
        if response.len() < 47 || response.first() != Some(&0x16) || response.get(5) != Some(&0x02)
        {
            return false;
        }

        let Some(record_len) = Self::read_u16_at(response, 3, "NPN ServerHello record length")
            .ok()
            .map(usize::from)
        else {
            return false;
        };
        if 5 + record_len > response.len() {
            return false;
        }

        let Some(sid_len) = Self::read_u8_at(response, 43, "NPN ServerHello session ID length")
            .ok()
            .map(usize::from)
        else {
            return false;
        };
        let min_after_sid = 44 + sid_len + 2 + 1;
        min_after_sid <= response.len()
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

    /// Parse NPN protocols from ServerHello using structured TLS extension parsing
    fn parse_npn_response(&self, response: &[u8]) -> Result<Vec<String>> {
        let mut protocols = Vec::new();
        const MAX_PROTOCOLS: usize = 100;

        // Need at least: record header (5) + handshake header (4) + version (2) + random (32) + sid_len (1) = 44
        if response.len() < 44 || response.first() != Some(&0x16) || response.get(5) != Some(&0x02)
        {
            return Ok(protocols);
        }

        // Parse ServerHello structurally to find extensions
        let sid_len = Self::read_u8_at(response, 43, "NPN ServerHello session ID length")? as usize;
        // cipher suite (2) + compression (1) + extensions_length (2)
        let Some(ext_len_offset) = 44usize
            .checked_add(sid_len)
            .and_then(|offset| offset.checked_add(2 + 1))
        else {
            return Ok(protocols);
        };
        let Some(ext_start) = ext_len_offset.checked_add(2) else {
            return Ok(protocols);
        };
        if ext_start > response.len() {
            return Ok(protocols);
        }

        let ext_total =
            Self::read_u16_at(response, ext_len_offset, "NPN extensions length")? as usize;
        let ext_end =
            ext_start
                .checked_add(ext_total)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "NPN extension block length overflow".to_string(),
                })?;
        if ext_end > response.len() {
            return Err(crate::TlsError::ParseError {
                message: "NPN extension block extends beyond declared length".to_string(),
            });
        }

        // Walk extensions structurally
        let mut pos = ext_start;
        while let Some(ext_header_end) = pos.checked_add(4).filter(|&end| end <= ext_end) {
            let ext_type = Self::read_u16_at(response, pos, "NPN extension type")?;
            let ext_len_offset = pos
                .checked_add(2)
                .ok_or_else(|| crate::TlsError::ParseError {
                    message: "NPN extension length offset overflow".to_string(),
                })?;
            let ext_len =
                Self::read_u16_at(response, ext_len_offset, "NPN extension length")? as usize;
            pos = ext_header_end;
            let ext_data_end =
                pos.checked_add(ext_len)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "NPN extension data length overflow".to_string(),
                    })?;
            if ext_data_end > ext_end {
                return Err(crate::TlsError::ParseError {
                    message: "NPN extension data extends beyond declared length".to_string(),
                });
            }

            if ext_type == 0x3374 {
                // Parse NPN protocol list
                let npn_end = ext_data_end;
                let mut npn_pos = pos;
                while npn_pos < npn_end
                    && npn_pos < response.len()
                    && protocols.len() < MAX_PROTOCOLS
                {
                    let proto_len =
                        Self::read_u8_at(response, npn_pos, "NPN protocol name length")? as usize;
                    npn_pos += 1;
                    if proto_len == 0 {
                        return Err(crate::TlsError::ParseError {
                            message: "NPN protocol name length cannot be zero".to_string(),
                        });
                    }
                    let proto_end = npn_pos.checked_add(proto_len).ok_or_else(|| {
                        crate::TlsError::ParseError {
                            message: "NPN protocol name length overflow".to_string(),
                        }
                    })?;
                    if proto_end > npn_end {
                        return Err(crate::TlsError::ParseError {
                            message: "NPN protocol name extends beyond extension data".to_string(),
                        });
                    }
                    let proto = String::from_utf8(
                        Self::slice_range(response, npn_pos, proto_len, "NPN protocol name")?
                            .to_vec(),
                    )
                    .map_err(|error| crate::TlsError::ParseError {
                        message: format!("Invalid NPN protocol name UTF-8: {error}"),
                    })?;
                    protocols.push(proto);
                    npn_pos = proto_end;
                }
                break;
            }

            pos = ext_data_end;
        }

        Ok(protocols)
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
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = NpnTester::new(target);

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

        let protocols = tester
            .parse_npn_response(&response)
            .expect("test assertion should succeed");
        assert_eq!(protocols, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn test_parse_npn_response_rejects_invalid_protocol_utf8() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = NpnTester::new(target);

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

        let err = tester
            .parse_npn_response(&response)
            .expect_err("invalid protocol UTF-8 should fail");
        assert!(err.to_string().contains("Invalid NPN protocol name UTF-8"));
    }

    #[test]
    fn test_parse_npn_response_invalid_data() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = NpnTester::new(target);

        // Not a valid ServerHello - should return empty
        let response = vec![0x33, 0x74, 0xff, 0xff];
        let protocols = tester
            .parse_npn_response(&response)
            .expect("test assertion should succeed");
        assert!(protocols.is_empty());
    }

    #[test]
    fn test_parse_npn_response_without_extension() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = NpnTester::new(target);

        // Too short for a ServerHello
        let response = vec![0x01, 0x02, 0x03, 0x04];
        let protocols = tester
            .parse_npn_response(&response)
            .expect("test assertion should succeed");
        assert!(protocols.is_empty());
    }

    #[test]
    fn test_parse_npn_response_truncated() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = NpnTester::new(target);

        // Truncated data - not a valid ServerHello
        let mut response = vec![0x16, 0x03, 0x03, 0x00, 0x02];
        response.push(0x03);
        response.push(b'h');

        let protocols = tester
            .parse_npn_response(&response)
            .expect("test assertion should succeed");
        assert!(protocols.is_empty());
    }

    #[test]
    fn test_parse_npn_response_rejects_truncated_extension_data() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = NpnTester::new(target);

        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record header
            0x02, 0x00, 0x00, 0x00, // ServerHello header
            0x03, 0x03, // version
        ];
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00); // session id len
        response.extend_from_slice(&[0x00, 0x9c]); // cipher
        response.push(0x00); // compression
        response.extend_from_slice(&[0x00, 0x04]); // extensions len
        response.extend_from_slice(&[0x33, 0x74, 0x00, 0x02]); // NPN ext claims 2 bytes
        response.push(0x01); // truncated protocol list

        let err = tester
            .parse_npn_response(&response)
            .expect_err("truncated NPN extension should fail");
        assert!(
            err.to_string()
                .contains("NPN extension data extends beyond declared length")
        );
    }

    #[test]
    fn test_parse_npn_response_rejects_truncated_extension_block() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = NpnTester::new(target);

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

        let err = tester
            .parse_npn_response(&response)
            .expect_err("truncated extension block should fail");
        assert!(
            err.to_string()
                .contains("NPN extension block extends beyond declared length")
        );
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
}
