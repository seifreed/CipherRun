// CCS Injection (ChangeCipherSpec Injection) Vulnerability Test
// CVE-2014-0224
//
// CCS Injection allows an attacker to force the use of weak cryptographic material
// by injecting a ChangeCipherSpec message early in the handshake process.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// CCS Injection vulnerability tester
pub struct CcsInjectionTester {
    target: Target,
}

impl CcsInjectionTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for CCS Injection vulnerability
    pub async fn test(&self) -> Result<CcsTestResult> {
        let vulnerable = self.test_ccs_injection().await?;

        let details = if vulnerable {
            "Vulnerable to CCS Injection (CVE-2014-0224) - Server accepts early CCS messages"
                .to_string()
        } else {
            "Not vulnerable - Server rejects early CCS messages".to_string()
        };

        Ok(CcsTestResult {
            vulnerable,
            details,
        })
    }

    /// Test CCS injection by sending early ChangeCipherSpec
    async fn test_ccs_injection(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send TLS ClientHello
                let client_hello = self.build_client_hello();
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; 4096];
                let n = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await??;

                if n == 0 {
                    return Ok(false);
                }

                // Send premature ChangeCipherSpec (before key exchange)
                let ccs = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
                stream.write_all(&ccs).await?;

                // Try to read response
                let mut response = vec![0u8; 1024];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // If server responds positively, it's vulnerable
                        // Check for Alert or normal handshake continuation
                        if response[0] == 0x15 {
                            // Alert - not vulnerable
                            Ok(false)
                        } else {
                            // Continues handshake - vulnerable
                            Ok(true)
                        }
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Build a basic TLS ClientHello message
    fn build_client_hello(&self) -> Vec<u8> {
        let mut hello = vec![
            0x16, 0x03, 0x01, // TLS Record Layer (Handshake, TLS 1.0)
            0x00, 0x00, // Length placeholder
            0x01, // Handshake Protocol (ClientHello)
            0x00, 0x00, 0x00, // Handshake length placeholder
        ];

        // Version TLS 1.0
        hello.push(0x03);
        hello.push(0x01);

        // Random (32 bytes)
        hello.extend_from_slice(&[0x00; 32]);

        // Session ID (empty)
        hello.push(0x00);

        // Cipher Suites length
        hello.push(0x00);
        hello.push(0x02);

        // Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA
        hello.push(0x00);
        hello.push(0x2f);

        // Compression methods length
        hello.push(0x01);
        hello.push(0x00); // No compression

        // Calculate and update lengths
        let handshake_len = (hello.len() - 9) as u32;
        hello[6] = ((handshake_len >> 16) & 0xff) as u8;
        hello[7] = ((handshake_len >> 8) & 0xff) as u8;
        hello[8] = (handshake_len & 0xff) as u8;

        let record_len = (hello.len() - 5) as u16;
        hello[3] = ((record_len >> 8) & 0xff) as u8;
        hello[4] = (record_len & 0xff) as u8;

        hello
    }
}

/// CCS test result
#[derive(Debug, Clone)]
pub struct CcsTestResult {
    pub vulnerable: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_build() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = CcsInjectionTester::new(target);
        let hello = tester.build_client_hello();

        assert!(hello.len() > 40);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[test]
    fn test_ccs_result_creation() {
        let result = CcsTestResult {
            vulnerable: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
    }
}
