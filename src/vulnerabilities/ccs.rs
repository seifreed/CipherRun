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
        let status = self.test_ccs_injection().await?;

        let details = match status {
            TestStatus::Vulnerable => {
                "Vulnerable to CCS Injection (CVE-2014-0224) - Server accepts early CCS messages"
                    .to_string()
            }
            TestStatus::NotVulnerable => {
                "Not vulnerable - Server rejects early CCS messages".to_string()
            }
            TestStatus::Inconclusive => {
                "CCS Injection test inconclusive - unexpected response pattern".to_string()
            }
            TestStatus::ConnectionFailed => {
                "CCS Injection test inconclusive - connection failed".to_string()
            }
            TestStatus::HandshakeFailed => {
                "CCS Injection test inconclusive - handshake timeout or error".to_string()
            }
        };

        Ok(CcsTestResult {
            vulnerable: status.is_vulnerable(),
            status,
            details,
        })
    }

    /// Test CCS injection by sending early ChangeCipherSpec
    async fn test_ccs_injection(&self) -> Result<TestStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

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
                        return Ok(TestStatus::HandshakeFailed);
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("CCS test read error during ServerHello: {}", e);
                        return Ok(TestStatus::HandshakeFailed);
                    }
                    Err(_) => {
                        tracing::debug!("CCS test timeout during ServerHello");
                        return Ok(TestStatus::HandshakeFailed);
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
                // Allow up to 15 handshake messages for complex handshakes (Certificate,
                // CertificateStatus, ServerKeyExchange, CertificateRequest, ServerHelloDone, etc.)
                const MAX_HANDSHAKE_MESSAGES: u8 = 15;
                let mut reads_remaining: u8 = MAX_HANDSHAKE_MESSAGES;
                // Accumulate bytes across reads so TLS records split across multiple
                // read() calls are reassembled before parsing.
                let mut accumulated: Vec<u8> = Vec::new();
                loop {
                    let mut read_buf = vec![0u8; 1024];
                    match timeout(Duration::from_secs(2), stream.read(&mut read_buf)).await {
                        Ok(Ok(n)) if n > 0 => {
                            accumulated.extend_from_slice(&read_buf[..n]);
                            // A single read() may return multiple concatenated TLS records.
                            // Scan all complete records; carry forward any partial tail.
                            let mut offset = 0usize;
                            let mut result: Option<TestStatus> = None;
                            while offset + 5 <= accumulated.len() {
                                let record_type = accumulated[offset];
                                let record_len = u16::from_be_bytes([
                                    accumulated[offset + 3],
                                    accumulated[offset + 4],
                                ]) as usize;

                                if offset + 5 + record_len > accumulated.len() {
                                    // Record not yet complete — wait for more data
                                    break;
                                }

                                if record_type == CONTENT_TYPE_ALERT {
                                    result = Some(TestStatus::NotVulnerable);
                                    break;
                                } else if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
                                    result = Some(TestStatus::Vulnerable);
                                    break;
                                } else if record_type == CONTENT_TYPE_HANDSHAKE
                                    && offset + 6 <= accumulated.len()
                                {
                                    let handshake_type = accumulated[offset + 5];
                                    if matches!(handshake_type, 0x0B | 0x0C | 0x0D | 0x0E | 0x02) {
                                        // Normal handshake continuation — skip this record
                                        reads_remaining = reads_remaining.saturating_sub(1);
                                        if reads_remaining == 0 {
                                            tracing::debug!(
                                                "Reached max handshake message limit ({}), assuming not vulnerable",
                                                MAX_HANDSHAKE_MESSAGES
                                            );
                                            result = Some(TestStatus::NotVulnerable);
                                            break;
                                        }
                                        offset += 5 + record_len;
                                        continue;
                                    } else {
                                        result = Some(TestStatus::Inconclusive);
                                        break;
                                    }
                                } else {
                                    result = Some(TestStatus::Inconclusive);
                                    break;
                                }
                            }

                            // Discard fully processed bytes; keep the partial record tail
                            accumulated.drain(..offset);

                            if let Some(status) = result {
                                break Ok(status);
                            }
                            // All complete records were handshake continuations; read more
                            continue;
                        }
                        Ok(Ok(_)) => {
                            // Zero bytes — connection closed, not vulnerable
                            break Ok(TestStatus::NotVulnerable);
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Timeout or error — inconclusive
                            break Ok(TestStatus::Inconclusive);
                        }
                    }
                }
            }
            Err(_) => {
                // Connection failed
                Ok(TestStatus::ConnectionFailed)
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

/// CCS test status with detailed failure reasons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// Server correctly rejected CCS - not vulnerable
    NotVulnerable,
    /// Server accepted CCS - vulnerable to CVE-2014-0224
    Vulnerable,
    /// Connection or handshake error - test inconclusive
    Inconclusive,
    /// Connection failed to establish
    ConnectionFailed,
    /// Handshake failed during ServerHello read
    HandshakeFailed,
}

impl TestStatus {
    /// Returns true if the test result indicates vulnerability
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, Self::Vulnerable)
    }

    /// Returns true if the test could not complete
    pub fn is_inconclusive(&self) -> bool {
        matches!(
            self,
            Self::Inconclusive | Self::ConnectionFailed | Self::HandshakeFailed
        )
    }
}

/// CCS test result
#[derive(Debug, Clone)]
pub struct CcsTestResult {
    pub vulnerable: bool,
    pub status: TestStatus,
    pub details: String,
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
            status: TestStatus::NotVulnerable,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(!result.status.is_inconclusive());
    }

    #[test]
    fn test_ccs_result_debug_contains_details() {
        let result = CcsTestResult {
            vulnerable: true,
            status: TestStatus::Vulnerable,
            details: "Details".to_string(),
        };

        let debug = format!("{:?}", result);
        assert!(debug.contains("Details"));
    }

    #[test]
    fn test_ccs_result_not_vulnerable_details() {
        let result = CcsTestResult {
            vulnerable: false,
            status: TestStatus::NotVulnerable,
            details: "Not vulnerable - Server rejects early CCS messages".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_ccs_result_details_passthrough() {
        let result = CcsTestResult {
            vulnerable: false,
            status: TestStatus::NotVulnerable,
            details: "Not vulnerable".to_string(),
        };
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_status_methods() {
        assert!(TestStatus::Vulnerable.is_vulnerable());
        assert!(!TestStatus::NotVulnerable.is_vulnerable());

        assert!(TestStatus::Inconclusive.is_inconclusive());
        assert!(TestStatus::ConnectionFailed.is_inconclusive());
        assert!(TestStatus::HandshakeFailed.is_inconclusive());
        assert!(!TestStatus::Vulnerable.is_inconclusive());
        assert!(!TestStatus::NotVulnerable.is_inconclusive());
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
        // Connection to inactive port should be marked as connection failed
        assert!(result.status.is_inconclusive());
        assert!(matches!(result.status, TestStatus::ConnectionFailed));
    }
}
