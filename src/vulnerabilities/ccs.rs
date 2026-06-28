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
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
}

impl CcsInjectionTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before the CCS probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
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

        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        match crate::utils::network::connect_with_starttls(
            addr,
            TLS_HANDSHAKE_TIMEOUT,
            self.starttls,
            &hostname,
        )
        .await
        {
            Ok(mut stream) => {
                // Send TLS ClientHello
                let client_hello = self.build_client_hello()?;
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; 4096];
                let _n = match timeout(
                    Duration::from_secs(3),
                    read_complete_tls_record(&mut stream, &mut buffer),
                )
                .await
                {
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
                // V7 fix: an outer iteration cap bounds total wall time on
                // servers that dribble bytes one at a time. `reads_remaining`
                // only decrements when a FULL handshake record is consumed, so
                // an adversarial peer could otherwise loop forever by always
                // leaving the tail record incomplete.
                const MAX_TOTAL_ITERATIONS: u32 = 100;
                let mut reads_remaining: u8 = MAX_HANDSHAKE_MESSAGES;
                let mut total_iterations: u32 = 0;
                // Accumulate bytes across reads so TLS records split across multiple
                // read() calls are reassembled before parsing.
                let mut accumulated: Vec<u8> = Vec::new();
                loop {
                    total_iterations += 1;
                    if total_iterations > MAX_TOTAL_ITERATIONS {
                        tracing::warn!(
                            "CCS: exceeded {} outer read iterations — aborting probe as inconclusive",
                            MAX_TOTAL_ITERATIONS
                        );
                        break Ok(TestStatus::Inconclusive);
                    }
                    let mut read_buf = vec![0u8; 1024];
                    match timeout(Duration::from_secs(2), stream.read(&mut read_buf)).await {
                        Ok(Ok(n)) if n > 0 => {
                            let bytes =
                                read_buf
                                    .get(..n)
                                    .ok_or_else(|| crate::TlsError::ParseError {
                                        message: "CCS response read length exceeded buffer"
                                            .to_string(),
                                    })?;
                            accumulated.extend_from_slice(bytes);
                            // A single read() may return multiple concatenated TLS records.
                            // Scan all complete records; carry forward any partial tail.
                            let mut offset = 0usize;
                            let mut result: Option<TestStatus> = None;
                            while let Some(header_end) = offset
                                .checked_add(5)
                                .filter(|&end| end <= accumulated.len())
                            {
                                let Some(record_header) = accumulated
                                    .get(offset..header_end)
                                    .and_then(|header| <&[u8; 5]>::try_from(header).ok())
                                else {
                                    result = Some(TestStatus::Inconclusive);
                                    break;
                                };
                                let record_type = record_header[0];
                                let record_len =
                                    u16::from_be_bytes([record_header[3], record_header[4]])
                                        as usize;

                                let Some(record_end) = header_end.checked_add(record_len) else {
                                    result = Some(TestStatus::Inconclusive);
                                    break;
                                };
                                if record_end > accumulated.len() {
                                    // Record not yet complete — wait for more data
                                    break;
                                }

                                if record_type == CONTENT_TYPE_ALERT {
                                    result = Some(
                                        if accumulated.get(offset..).is_some_and(|record| {
                                            alert_record_is_complete(record, 5 + record_len)
                                        }) {
                                            TestStatus::NotVulnerable
                                        } else {
                                            TestStatus::Inconclusive
                                        },
                                    );
                                    break;
                                } else if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
                                    result = Some(TestStatus::Vulnerable);
                                    break;
                                } else if record_type == CONTENT_TYPE_HANDSHAKE {
                                    // ServerHello(0x02), Certificate(0x0B),
                                    // ServerKeyExchange(0x0C), CertificateRequest(0x0D),
                                    // ServerHelloDone(0x0E), CertificateStatus(0x16, OCSP
                                    // stapling). Omitting CertificateStatus made
                                    // stapling servers fall through to Inconclusive
                                    // instead of a conclusive not-vulnerable verdict.
                                    if accumulated.get(offset..record_end).is_some_and(|record| {
                                        handshake_record_is_normal_continuation(record, record_len)
                                    }) {
                                        // Normal handshake continuation — skip this record
                                        reads_remaining = reads_remaining.saturating_sub(1);
                                        if reads_remaining == 0 {
                                            tracing::debug!(
                                                "Reached max handshake message limit ({}), treating probe as inconclusive",
                                                MAX_HANDSHAKE_MESSAGES
                                            );
                                            result = Some(TestStatus::Inconclusive);
                                            break;
                                        }
                                        offset = record_end;
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
    fn build_client_hello(&self) -> Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
        builder.for_rsa_key_exchange();
        builder.build_minimal()
    }
}

fn alert_record_is_complete(buffer: &[u8], n: usize) -> bool {
    if n < 7 || buffer.first() != Some(&CONTENT_TYPE_ALERT) {
        return false;
    }
    let Some(alert_record_len) = buffer
        .get(3..5)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
    else {
        return false;
    };
    alert_record_len == 2 && n == 5 + alert_record_len
}

fn handshake_record_is_normal_continuation(record: &[u8], record_len: usize) -> bool {
    if record.first() != Some(&CONTENT_TYPE_HANDSHAKE) || record.len() != 5 + record_len {
        return false;
    }
    if record_len < 4 {
        return false;
    }
    matches!(
        record.get(5).copied(),
        Some(0x02 | 0x0B | 0x0C | 0x0D | 0x0E | 0x16)
    )
}

async fn read_complete_tls_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = 5usize
        .checked_add(record_len)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "CCS TLS record length overflow".to_string(),
        })?;
    if total_len > buffer.len() {
        return Err(crate::TlsError::ParseError {
            message: "CCS TLS record length exceeds buffer".to_string(),
        });
    }

    buffer[..5].copy_from_slice(&header);
    stream.read_exact(&mut buffer[5..total_len]).await?;
    Ok(total_len)
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
    use std::time::Duration;
    use tokio::net::TcpListener as TokioTcpListener;

    #[test]
    fn test_client_hello_build() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CcsInjectionTester::new(target);
        let hello = tester
            .build_client_hello()
            .expect("ClientHello should build");

        assert!(hello.len() > 40);
        assert_eq!(hello.first(), Some(&CONTENT_TYPE_HANDSHAKE)); // Handshake (0x16)
        assert_eq!(hello.get(5), Some(&HANDSHAKE_TYPE_CLIENT_HELLO)); // ClientHello (0x01)
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
        let hello = tester
            .build_client_hello()
            .expect("ClientHello should build");

        assert_eq!(hello.get(1), Some(&0x03));
        assert_eq!(hello.get(2), Some(&0x01));
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
        let hello = tester
            .build_client_hello()
            .expect("ClientHello should build");
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

    #[test]
    fn test_alert_record_is_complete_rejects_trailing_bytes() {
        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00];
        assert!(!alert_record_is_complete(&alert, alert.len()));
    }

    #[test]
    fn test_handshake_continuation_rejects_empty_record() {
        let record = [CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x00];
        assert!(!handshake_record_is_normal_continuation(&record, 0));
    }

    #[test]
    fn test_handshake_continuation_accepts_server_hello_done() {
        let record = [
            CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x04,
            0x0e,
            0x00,
            0x00,
            0x00,
        ];
        assert!(handshake_record_is_normal_continuation(&record, 4));
    }

    #[tokio::test]
    async fn test_read_complete_tls_record_handles_fragmented_header_and_body() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let record = [0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00];
            socket.write_all(&record[..3]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            socket.write_all(&record[3..6]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            socket.write_all(&record[6..]).await.unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buffer = vec![0u8; 32];
        let n = read_complete_tls_record(&mut stream, &mut buffer)
            .await
            .unwrap();

        assert_eq!(n, 9);
        assert_eq!(&buffer[..n], &[0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00]);

        server.await.unwrap();
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

    #[tokio::test]
    async fn test_ccs_injection_handshake_limit_is_inconclusive() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let record = [0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00];
            for _ in 0..16 {
                socket.write_all(&record).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let tester = CcsInjectionTester::new(target);
        let result = tester.test().await.unwrap();
        server.await.unwrap();

        assert!(result.status.is_inconclusive(), "{result:?}");
        assert!(!result.vulnerable);
        assert!(matches!(result.status, TestStatus::Inconclusive));
    }
}
