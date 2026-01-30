// NPN (Next Protocol Negotiation) Testing
// NPN was the predecessor to ALPN (Application Layer Protocol Negotiation)
// It's now deprecated in favor of ALPN, but some servers still support it

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// NPN protocol tester
pub struct NpnTester {
    target: Target,
}

impl NpnTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test if NPN is supported
    pub async fn test(&self) -> Result<NpnTestResult> {
        let supported_protocols = self.test_npn_support().await?;
        let supported = !supported_protocols.is_empty();

        let details = if supported {
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
        })
    }

    /// Test NPN support by sending ClientHello with NPN extension
    async fn test_npn_support(&self) -> Result<Vec<String>> {
        // Use raw TLS handshake to properly test NPN
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello with NPN extension
                let client_hello = self.build_client_hello_with_npn();
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; 8192];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Parse ServerHello for NPN extension
                        let protocols = self.parse_npn_response(&buffer[..n])?;
                        Ok(protocols)
                    }
                    _ => Ok(Vec::new()),
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Build ClientHello with NPN extension
    fn build_client_hello_with_npn(&self) -> Vec<u8> {
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
        for i in 0..32 {
            hello.push((i * 7) as u8);
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
        hello[ext_pos] = ((ext_len >> 8) & 0xff) as u8;
        hello[ext_pos + 1] = (ext_len & 0xff) as u8;

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        hello[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
        hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        // Update record length
        let rec_len = hello.len() - len_pos - 2;
        hello[len_pos] = ((rec_len >> 8) & 0xff) as u8;
        hello[len_pos + 1] = (rec_len & 0xff) as u8;

        hello
    }

    /// Parse NPN protocols from ServerHello
    fn parse_npn_response(&self, response: &[u8]) -> Result<Vec<String>> {
        let mut protocols = Vec::new();

        // Look for NPN extension (0x3374) in ServerHello
        for i in 0..response.len().saturating_sub(4) {
            if response[i] == 0x33 && response[i + 1] == 0x74 {
                // Found NPN extension
                if i + 3 < response.len() {
                    let ext_len = u16::from_be_bytes([response[i + 2], response[i + 3]]);
                    let start = i + 4;
                    let end = start + ext_len as usize;

                    if end <= response.len() {
                        // Parse protocol list
                        let mut pos = start;
                        while pos < end {
                            if pos < response.len() {
                                let proto_len = response[pos] as usize;
                                pos += 1;

                                if pos + proto_len <= end && pos + proto_len <= response.len() {
                                    if let Ok(proto) =
                                        String::from_utf8(response[pos..pos + proto_len].to_vec())
                                    {
                                        protocols.push(proto);
                                    }
                                    pos += proto_len;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                break;
            }
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
        };
        assert!(!result.supported);
        assert!(result.protocols.is_empty());
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
        let hello = tester.build_client_hello_with_npn();

        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello

        // Check for NPN extension (0x3374)
        let has_npn = hello.windows(2).any(|w| w == [0x33, 0x74]);
        assert!(has_npn);
    }
}
