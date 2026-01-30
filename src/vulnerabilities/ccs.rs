// CCS Injection (ChangeCipherSpec Injection) Vulnerability Test
// CVE-2014-0224
//
// CCS Injection allows an attacker to force the use of weak cryptographic material
// by injecting a ChangeCipherSpec message early in the handshake process.

use crate::Result;
use crate::constants::{CONTENT_TYPE_ALERT, CONTENT_TYPE_CHANGE_CIPHER_SPEC, VERSION_TLS_1_2};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
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
                let ccs = vec![
                    CONTENT_TYPE_CHANGE_CIPHER_SPEC, // 0x14
                    (VERSION_TLS_1_2 >> 8) as u8,    // 0x03
                    (VERSION_TLS_1_2 & 0xff) as u8,  // 0x03
                    0x00,
                    0x01, // Length: 1 byte
                    0x01, // CCS message
                ];
                stream.write_all(&ccs).await?;

                // Try to read response
                let mut response = vec![0u8; 1024];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // If server responds positively, it's vulnerable
                        // Check for Alert or normal handshake continuation
                        if response[0] == CONTENT_TYPE_ALERT {
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

    /// Build a basic TLS ClientHello message using ClientHelloBuilder
    fn build_client_hello(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
        builder.for_rsa_key_exchange();
        builder.build_minimal().unwrap_or_else(|_| Vec::new())
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
    use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO};

    #[test]
    fn test_client_hello_build() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CcsInjectionTester::new(target);
        let hello = tester.build_client_hello();

        assert!(hello.len() > 40);
        assert_eq!(hello[0], CONTENT_TYPE_HANDSHAKE); // Handshake (0x16)
        assert_eq!(hello[5], HANDSHAKE_TYPE_CLIENT_HELLO); // ClientHello (0x01)
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
