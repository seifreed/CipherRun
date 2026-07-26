// NPN (Next Protocol Negotiation) Testing
// NPN was the predecessor to ALPN (Application Layer Protocol Negotiation)
// It's now deprecated in favor of ALPN, but some servers still support it

use crate::Result;
use crate::constants::TLS_RECORD_HEADER_SIZE;
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

                    let Some(total_len) = crate::protocols::tls_record::total_len(&header)? else {
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
            len_bytes.copy_from_slice(
                &crate::protocols::tls_vector::u16_len(ext_len, "NPN extensions")?.to_be_bytes(),
            );
        }

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        if let Some(len_bytes) = hello.get_mut(hs_len_pos..hs_len_pos + 3) {
            len_bytes.copy_from_slice(&crate::protocols::tls_vector::u24_len(
                hs_len,
                "NPN handshake",
            )?);
        }

        // Update record length
        let rec_len = hello.len() - len_pos - 2;
        if let Some(len_bytes) = hello.get_mut(len_pos..len_pos + 2) {
            len_bytes.copy_from_slice(
                &crate::protocols::tls_vector::u16_len(rec_len, "NPN record")?.to_be_bytes(),
            );
        }

        Ok(hello)
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

    const NPN_H2_HTTP11_EXTENSION: &[u8] = &[
        0x33, 0x74, 0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.',
        b'1',
    ];

    fn parse_npn_response(response: &[u8]) -> Result<Vec<String>> {
        server_hello::parse_npn_protocols(response)
    }

    fn npn_server_hello(extension_data: &[u8], declared_ext_len: Option<u16>) -> Vec<u8> {
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
        response.extend_from_slice(extension_data);

        let ext_len = declared_ext_len.unwrap_or((response.len() - ext_len_pos - 2) as u16);
        response[ext_len_pos] = (ext_len >> 8) as u8;
        response[ext_len_pos + 1] = (ext_len & 0xff) as u8;
        patch_server_hello_lengths(&mut response);
        response
    }

    fn patch_server_hello_lengths(response: &mut [u8]) {
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;
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
        let response = npn_server_hello(NPN_H2_HTTP11_EXTENSION, None);

        let protocols = parse_npn_response(&response).expect("test assertion should succeed");
        assert_eq!(protocols, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn test_parse_npn_response_rejects_invalid_protocol_utf8() {
        let response = npn_server_hello(&[0x33, 0x74, 0x00, 0x02, 0x01, 0xff], None);

        let err = parse_npn_response(&response).expect_err("invalid protocol UTF-8 should fail");
        assert!(err.to_string().contains("Invalid NPN protocol name UTF-8"));
    }

    #[test]
    fn test_parse_npn_response_returns_empty_for_non_server_hello_inputs() {
        for (case, response) in [
            ("invalid data", vec![0x33, 0x74, 0xff, 0xff]),
            ("too short", vec![0x01, 0x02, 0x03, 0x04]),
            ("truncated", vec![0x16, 0x03, 0x03, 0x00, 0x02, 0x03, b'h']),
        ] {
            let protocols = parse_npn_response(&response).expect(case);
            assert!(protocols.is_empty(), "{case}");
        }
    }

    #[test]
    fn test_parse_npn_response_rejects_malformed_extensions() {
        for (case, response, expected) in [
            (
                "truncated NPN extension",
                npn_server_hello(&[0x33, 0x74, 0x00, 0x02, 0x01], None),
                "NPN extension data extends beyond declared length",
            ),
            (
                "truncated extension block",
                npn_server_hello(
                    NPN_H2_HTTP11_EXTENSION,
                    Some(NPN_H2_HTTP11_EXTENSION.len() as u16 + 1),
                ),
                "NPN extension block extends beyond handshake length",
            ),
            (
                "trailing extension bytes",
                npn_server_hello(&[0xff], Some(0)),
                "NPN extension block contains trailing bytes",
            ),
            (
                "truncated extension header",
                npn_server_hello(&[0x33, 0x74, 0x00], None),
                "NPN extension block contains truncated header",
            ),
        ] {
            let err = parse_npn_response(&response).expect_err(case);
            assert!(err.to_string().contains(expected), "{case}");
        }
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

                let response = npn_server_hello(NPN_H2_HTTP11_EXTENSION, None);

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
