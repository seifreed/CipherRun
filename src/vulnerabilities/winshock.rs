// Winshock Vulnerability Test
// MS14-066, CVE-2014-6321
//
// Winshock is a vulnerability in Microsoft's Schannel (Windows TLS/SSL implementation)
// that allows remote code execution. The vulnerability exists in how Schannel processes
// specially crafted TLS packets during the handshake phase.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Winshock vulnerability tester
pub struct WinshockTester {
    target: Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchannelDetectionStatus {
    Detected,
    NotDetected,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MalformedHandshakeStatus {
    Vulnerable,
    Handled,
    Inconclusive,
}

impl WinshockTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Winshock vulnerability
    pub async fn test(&self) -> Result<WinshockTestResult> {
        let schannel_status = self.detect_schannel().await?;
        if schannel_status == SchannelDetectionStatus::Inconclusive {
            return Ok(WinshockTestResult {
                vulnerable: false,
                schannel_detected: false,
                inconclusive: true,
                details:
                    "Winshock test inconclusive - unable to connect to target to detect Schannel"
                        .to_string(),
            });
        }

        let malformed_status = if schannel_status == SchannelDetectionStatus::Detected {
            Some(self.test_malformed_handshake().await?)
        } else {
            None
        };

        Ok(Self::build_result(schannel_status, malformed_status))
    }

    fn build_result(
        schannel_status: SchannelDetectionStatus,
        malformed_status: Option<MalformedHandshakeStatus>,
    ) -> WinshockTestResult {
        let schannel_detected = schannel_status == SchannelDetectionStatus::Detected;

        match (schannel_status, malformed_status) {
            (SchannelDetectionStatus::Detected, Some(MalformedHandshakeStatus::Vulnerable)) => {
                WinshockTestResult {
                    vulnerable: true,
                    schannel_detected: true,
                    inconclusive: false,
                    details: "Vulnerable to Winshock (MS14-066, CVE-2014-6321) - Server crashes or behaves abnormally with malformed handshake".to_string(),
                }
            }
            (SchannelDetectionStatus::Detected, Some(MalformedHandshakeStatus::Handled)) => {
                WinshockTestResult {
                    vulnerable: false,
                    schannel_detected: true,
                    inconclusive: false,
                    details: "Schannel detected but Winshock test passed - Likely patched or protected".to_string(),
                }
            }
            (SchannelDetectionStatus::Detected, Some(MalformedHandshakeStatus::Inconclusive)) => {
                WinshockTestResult {
                    vulnerable: false,
                    schannel_detected: true,
                    inconclusive: true,
                    details: "Winshock test inconclusive - Schannel was detected, but malformed handshake probe did not produce conclusive evidence".to_string(),
                }
            }
            _ => WinshockTestResult {
                vulnerable: false,
                schannel_detected,
                inconclusive: false,
                details: "Not vulnerable - Schannel not detected".to_string(),
            },
        }
    }

    /// Detect if server is using Microsoft Schannel
    async fn detect_schannel(&self) -> Result<SchannelDetectionStatus> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(SchannelDetectionStatus::Inconclusive),
            };

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

                // Schannel's top-negotiated ciphers. We check exact equality on the
                // negotiated cipher (not substring) to avoid flagging servers that merely
                // support these widely-used suites but prefer something else first.
                let schannel_ciphers = [
                    "ECDHE-RSA-AES256-SHA384",
                    "ECDHE-RSA-AES128-SHA256",
                    "AES256-SHA256",
                    "AES128-SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "ECDHE-ECDSA-AES256-GCM-SHA384",
                    "ECDHE-ECDSA-AES128-GCM-SHA256",
                ];

                if schannel_ciphers.contains(&cipher.as_str()) {
                    Ok(SchannelDetectionStatus::Detected)
                } else {
                    Ok(SchannelDetectionStatus::NotDetected)
                }
            }
            Err(_) => Ok(SchannelDetectionStatus::NotDetected),
        }
    }

    /// Test with malformed handshake that triggers Winshock
    async fn test_malformed_handshake(&self) -> Result<MalformedHandshakeStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let mut stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(MalformedHandshakeStatus::Inconclusive),
            };

        // Send normal ClientHello first
        let client_hello = self.build_client_hello();
        if client_hello.is_empty() {
            return Ok(MalformedHandshakeStatus::Inconclusive);
        }
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
                    Ok(Ok(n)) if n > 0 => {
                        // Any server response (TLS alert 0x15 or other) means it handled
                        // the malformed CKE without crashing. TCP RST (below) is the
                        // primary Winshock indicator.
                        Ok(MalformedHandshakeStatus::Handled)
                    }
                    Ok(Ok(_)) => {
                        // Empty response - connection closed without error
                        Ok(MalformedHandshakeStatus::Handled)
                    }
                    Ok(Err(e)) => {
                        // Connection error - analyze the error type
                        let error_str = e.to_string();
                        // Connection reset could indicate vulnerability, but also
                        // network issues. We should NOT mark ALL errors as vulnerable.
                        // Mark as NOT vulnerable to avoid false positives.
                        // Manual verification needed for suspicious connection resets.
                        if error_str.contains("reset by peer")
                            || error_str.contains("connection reset")
                        {
                            // Winshock causes memory corruption → process crash → TCP RST.
                            // A connection reset after sending the malformed CKE is the
                            // primary positive indicator for CVE-2014-6321.
                            Ok(MalformedHandshakeStatus::Vulnerable)
                        } else {
                            Ok(MalformedHandshakeStatus::Inconclusive)
                        }
                    }
                    Err(_) => Ok(MalformedHandshakeStatus::Inconclusive),
                }
            }
            _ => Ok(MalformedHandshakeStatus::Inconclusive),
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
    pub inconclusive: bool,
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
            inconclusive: false,
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

    #[test]
    fn test_client_hello_builder_structure() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = WinshockTester::new(target);
        let hello = tester.build_client_hello();

        assert!(hello.len() > 40);
        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[test]
    fn test_malformed_cke_contains_padding_pattern() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = WinshockTester::new(target);
        let malformed = tester.build_malformed_client_key_exchange();

        assert!(malformed.windows(4).any(|w| w == [0x41, 0x41, 0x41, 0x41]));
        assert!(malformed.len() >= 256);
    }

    #[test]
    fn test_malformed_cke_header_lengths() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = WinshockTester::new(target);
        let malformed = tester.build_malformed_client_key_exchange();

        assert_eq!(malformed[3], 0xff);
        assert_eq!(malformed[4], 0xff);
        assert_eq!(malformed[6], 0xff);
        assert_eq!(malformed[7], 0xff);
        assert_eq!(malformed[8], 0xff);
    }

    #[test]
    fn test_winshock_result_details() {
        let result = WinshockTestResult {
            vulnerable: false,
            schannel_detected: false,
            inconclusive: false,
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_winshock_result_debug_contains_fields() {
        let result = WinshockTestResult {
            vulnerable: true,
            schannel_detected: true,
            inconclusive: false,
            details: "Vulnerable".to_string(),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("schannel_detected"));
    }

    #[test]
    fn test_winshock_schannel_probe_failure_is_inconclusive() {
        let result = WinshockTester::build_result(
            SchannelDetectionStatus::Detected,
            Some(MalformedHandshakeStatus::Inconclusive),
        );

        assert!(!result.vulnerable);
        assert!(result.schannel_detected);
        assert!(result.inconclusive);
        assert!(result.details.contains("inconclusive"));
    }

    #[tokio::test]
    async fn test_winshock_inactive_target_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let tester = WinshockTester::new(target);
        let result = tester.test().await.unwrap();

        assert!(!result.vulnerable);
        assert!(!result.schannel_detected);
        assert!(result.inconclusive, "{result:?}");
        assert!(result.details.contains("inconclusive"), "{result:?}");
    }
}
