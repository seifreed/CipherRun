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
        let (vulnerable, inconclusive) = self.test_ccs_injection().await?;

        let details = if inconclusive {
            "CCS Injection test inconclusive - connection timeout or handshake failure prevented reliable testing".to_string()
        } else if vulnerable {
            "Vulnerable to CCS Injection (CVE-2014-0224) - Server accepts early CCS messages"
                .to_string()
        } else {
            "Not vulnerable - Server rejects early CCS messages".to_string()
        };

        Ok(CcsTestResult {
            vulnerable,
            details,
            inconclusive,
        })
    }

    /// Test CCS injection by sending early ChangeCipherSpec
    async fn test_ccs_injection(&self) -> Result<(bool, bool)> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send TLS ClientHello
                let client_hello = self.build_client_hello();
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; 4096];
                let _n = match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => n,
                    Ok(Ok(_)) => {
                        // Zero bytes read - connection closed by server
                        return Ok((false, true));
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Read error or timeout during ServerHello read
                        return Ok((false, true));
                    }
                };

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
                            Ok((false, false))
                        } else {
                            // Continues handshake - vulnerable
                            Ok((true, false))
                        }
                    }
                    Ok(Ok(_)) => {
                        // Zero bytes after CCS - connection closed, likely not vulnerable but inconclusive
                        Ok((false, true))
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Timeout or error - inconclusive
                        Ok((false, true))
                    }
                }
            }
            Ok(Err(_)) | Err(_) => {
                // Connection failed - inconclusive
                Ok((false, true))
            }
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
    pub inconclusive: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO};
    use std::net::TcpListener;

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
    fn test_client_hello_version_bytes() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CcsInjectionTester::new(target);
        let hello = tester.build_client_hello();

        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01);
    }

    #[test]
    fn test_client_hello_non_empty() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CcsInjectionTester::new(target);
        let hello = tester.build_client_hello();
        assert!(!hello.is_empty());
    }

    #[test]
    fn test_ccs_result_creation() {
        let result = CcsTestResult {
            vulnerable: false,
            details: "Test".to_string(),
            inconclusive: false,
        };
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_ccs_result_debug_contains_details() {
        let result = CcsTestResult {
            vulnerable: true,
            details: "Details".to_string(),
            inconclusive: false,
        };

        let debug = format!("{:?}", result);
        assert!(debug.contains("Details"));
    }

    #[test]
    fn test_ccs_result_not_vulnerable_details() {
        let result = CcsTestResult {
            vulnerable: false,
            details: "Not vulnerable - Server rejects early CCS messages".to_string(),
            inconclusive: false,
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_ccs_result_details_passthrough() {
        let result = CcsTestResult {
            vulnerable: false,
            details: "Not vulnerable".to_string(),
            inconclusive: false,
        };
        assert!(result.details.contains("Not vulnerable"));
    }

    #[tokio::test]
    async fn test_ccs_injection_inactive_target_not_vulnerable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let tester = CcsInjectionTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        // Connection to inactive port should be marked as inconclusive
        assert!(result.inconclusive);
    }
}
