// CCS Injection (ChangeCipherSpec Injection) Vulnerability Test
// CVE-2014-0224
//
// CCS Injection allows an attacker to force the use of weak cryptographic material
// by injecting a ChangeCipherSpec message early in the handshake process.

use crate::Result;
use crate::constants::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    TLS_HANDSHAKE_TIMEOUT, VERSION_TLS_1_0,
};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

        match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None).await {
            Ok(mut stream) => {
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
                // Use the same TLS version as the ClientHello (TLS 1.0)
                // CCS Injection affects TLS 1.0 and earlier where the CCS
                // is processed before the handshake is complete
                let ccs = vec![
                    CONTENT_TYPE_CHANGE_CIPHER_SPEC, // 0x14
                    (VERSION_TLS_1_0 >> 8) as u8,    // 0x03 - TLS version major
                    (VERSION_TLS_1_0 & 0xff) as u8,  // 0x01 - TLS version minor (TLS 1.0)
                    0x00,
                    0x01, // Length: 1 byte
                    0x01, // CCS message
                ];
                stream.write_all(&ccs).await?;

                // Read responses after sending premature CCS.
                // The server may still be sending handshake messages
                // (Certificate, ServerKeyExchange, ServerHelloDone) as part of the
                // original handshake -- these are NOT responses to our CCS.
                // We loop to consume all handshake continuation messages before
                // evaluating the actual CCS/Alert response.
                let mut reads_remaining: u8 = 5;
                loop {
                    let mut response = vec![0u8; 1024];
                    match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                        Ok(Ok(n)) if n > 0 => {
                            if response[0] == CONTENT_TYPE_ALERT {
                                // Alert = server rejected our premature CCS → not vulnerable
                                break Ok((false, false));
                            } else if response[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
                                // Server sent CCS in response to our premature CCS.
                                // This is the actual indicator of CVE-2014-0224.
                                break Ok((true, false));
                            } else if response[0] == CONTENT_TYPE_HANDSHAKE && n >= 6 {
                                let handshake_type = response[5];
                                // 0x0B = Certificate, 0x0C = ServerKeyExchange, 0x0E = ServerHelloDone
                                // These are normal handshake continuation, NOT a response to CCS.
                                if matches!(handshake_type, 0x0B | 0x0C | 0x0D | 0x0E | 0x02) {
                                    reads_remaining -= 1;
                                    if reads_remaining == 0 {
                                        // Too many handshake messages without CCS/Alert
                                        break Ok((false, false));
                                    }
                                    continue;
                                } else {
                                    // Unexpected handshake message after CCS — inconclusive
                                    break Ok((false, true));
                                }
                            } else {
                                // Unknown response type — inconclusive
                                break Ok((false, true));
                            }
                        }
                        Ok(Ok(_)) => {
                            // Zero bytes — connection closed, not vulnerable
                            break Ok((false, false));
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Timeout or error — inconclusive
                            break Ok((false, true));
                        }
                    }
                }
            }
            Err(_) => {
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
