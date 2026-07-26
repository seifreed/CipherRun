// CCS Injection (ChangeCipherSpec Injection) Vulnerability Test
// CVE-2014-0224
//
// CCS Injection allows an attacker to force the use of weak cryptographic material
// by injecting a ChangeCipherSpec message early in the handshake process.

use crate::Result;
use crate::constants::{
    BUFFER_SIZE_MAX_WITH_OVERHEAD, CONTENT_TYPE_ALERT, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE, TLS_HANDSHAKE_TIMEOUT, VERSION_TLS_1_0,
};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

mod client_hello;
mod read_io;
mod record_analysis;
mod result;

pub use result::{CcsTestResult, TestStatus};

/// CCS Injection vulnerability tester
pub struct CcsInjectionTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

impl CcsInjectionTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before the CCS probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
        server_mode: bool,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self.starttls_server_mode = server_mode;
        self
    }

    pub fn with_test_all_ips(mut self, test_all_ips: bool) -> Self {
        self.test_all_ips = test_all_ips;
        self
    }

    fn probe_addrs(&self) -> Result<Vec<std::net::SocketAddr>> {
        crate::utils::target_addrs::socket_addrs_for_probe(&self.target, self.test_all_ips)
    }

    /// Test for CCS Injection vulnerability
    pub async fn test(&self) -> Result<CcsTestResult> {
        Ok(CcsTestResult::from_status(self.test_ccs_injection().await?))
    }

    /// Test CCS injection by sending early ChangeCipherSpec
    async fn test_ccs_injection(&self) -> Result<TestStatus> {
        let mut status = TestStatus::NotVulnerable;
        for addr in self.probe_addrs()? {
            status = status.merge(self.test_ccs_injection_addr(addr).await?);
            if status == TestStatus::Vulnerable {
                break;
            }
        }
        Ok(status)
    }

    async fn test_ccs_injection_addr(&self, addr: std::net::SocketAddr) -> Result<TestStatus> {
        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        match crate::utils::network::connect_with_starttls(
            addr,
            TLS_HANDSHAKE_TIMEOUT,
            self.starttls,
            &hostname,
            self.starttls_server_mode,
        )
        .await
        {
            Ok(mut stream) => {
                // Send TLS ClientHello
                let client_hello = client_hello::minimal_tls10_rsa()?;
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
                let _n = match timeout(
                    Duration::from_secs(3),
                    read_io::read_complete_tls_record(&mut stream, &mut buffer),
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
                                            record_analysis::alert_is_complete(
                                                record,
                                                5 + record_len,
                                            )
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
                                        record_analysis::handshake_is_normal_continuation(
                                            record, record_len,
                                        )
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::BUFFER_SIZE_DEFAULT;
    use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO};
    use std::net::TcpListener;
    use std::time::Duration;
    use tokio::net::TcpListener as TokioTcpListener;

    fn localhost_target(port: u16) -> Target {
        Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn test_ccs_probe_addrs_honors_all_ips() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let single = CcsInjectionTester::new(target.clone())
            .probe_addrs()
            .unwrap();
        let all = CcsInjectionTester::new(target)
            .with_test_all_ips(true)
            .probe_addrs()
            .unwrap();

        assert_eq!(single.len(), 1);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_ccs_merge_keeps_inconclusive_over_clean() {
        assert_eq!(
            TestStatus::NotVulnerable.merge(TestStatus::HandshakeFailed),
            TestStatus::HandshakeFailed
        );
    }

    #[test]
    fn test_client_hello_build() {
        let hello = client_hello::minimal_tls10_rsa().expect("ClientHello should build");

        assert!(hello.len() > 40);
        assert_eq!(hello.first(), Some(&CONTENT_TYPE_HANDSHAKE)); // Handshake (0x16)
        assert_eq!(hello.get(1), Some(&0x03));
        assert_eq!(hello.get(2), Some(&0x01));
        assert_eq!(hello.get(5), Some(&HANDSHAKE_TYPE_CLIENT_HELLO)); // ClientHello (0x01)
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
        assert!(!record_analysis::alert_is_complete(&alert, alert.len()));
    }

    #[test]
    fn test_handshake_continuation_rejects_empty_record() {
        let record = [CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x00];
        assert!(!record_analysis::handshake_is_normal_continuation(
            &record, 0
        ));
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
        assert!(record_analysis::handshake_is_normal_continuation(
            &record, 4
        ));
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
        let n = read_io::read_complete_tls_record(&mut stream, &mut buffer)
            .await
            .unwrap();

        assert_eq!(n, 9);
        assert_eq!(
            &buffer[..n],
            &[0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00]
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_complete_tls_record_accepts_record_above_default_buffer() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let record_len = BUFFER_SIZE_DEFAULT as u16;
            let header = [
                CONTENT_TYPE_HANDSHAKE,
                0x03,
                0x03,
                (record_len >> 8) as u8,
                record_len as u8,
            ];
            socket.write_all(&header).await.unwrap();
            socket
                .write_all(&vec![0u8; BUFFER_SIZE_DEFAULT])
                .await
                .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        let n = read_io::read_complete_tls_record(&mut stream, &mut buffer)
            .await
            .unwrap();

        assert_eq!(n, 5 + BUFFER_SIZE_DEFAULT);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_ccs_injection_inactive_target_not_vulnerable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = localhost_target(port);

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

        let target = localhost_target(addr.port());

        let tester = CcsInjectionTester::new(target);
        let result = tester.test().await.unwrap();
        server.await.unwrap();

        assert!(result.status.is_inconclusive(), "{result:?}");
        assert!(!result.vulnerable);
        assert!(matches!(result.status, TestStatus::Inconclusive));
    }
}
