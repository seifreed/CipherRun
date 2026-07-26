// Winshock Vulnerability Test
// MS14-066, CVE-2014-6321
//
// Winshock is a vulnerability in Microsoft's Schannel (Windows TLS/SSL implementation)
// that allows remote code execution. The vulnerability exists in how Schannel processes
// specially crafted TLS packets during the handshake phase.

use crate::Result;
use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_HANDSHAKE_TIMEOUT};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

mod client_hello;
mod messages;
mod read_io;
mod result;

pub use result::WinshockTestResult;

/// Winshock vulnerability tester
pub struct WinshockTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchannelDetectionStatus {
    Detected,
    NotDetected,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MalformedHandshakeStatus {
    Handled,
    Inconclusive,
}

impl WinshockTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before each Winshock probe.
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

    /// Connect, upgrading via STARTTLS first for plaintext-first services.
    async fn starttls_connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<tokio::net::TcpStream> {
        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        crate::utils::network::connect_with_starttls(
            addr,
            timeout,
            self.starttls,
            &hostname,
            self.starttls_server_mode,
        )
        .await
    }

    /// Test for Winshock vulnerability
    pub async fn test(&self) -> Result<WinshockTestResult> {
        let schannel_status = self.detect_schannel().await?;
        if schannel_status == SchannelDetectionStatus::Inconclusive {
            return Ok(WinshockTestResult::inconclusive_schannel_probe());
        }

        let malformed_status = if schannel_status == SchannelDetectionStatus::Detected {
            Some(self.test_malformed_handshake().await?)
        } else {
            None
        };

        Ok(WinshockTestResult::from_probe_status(
            schannel_status,
            malformed_status,
        ))
    }

    /// Detect if server is using Microsoft Schannel
    async fn detect_schannel(&self) -> Result<SchannelDetectionStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return Ok(SchannelDetectionStatus::Inconclusive),
        };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let (hostname, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
        tokio::task::spawn_blocking(move || -> Result<SchannelDetectionStatus> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // Certificate validity is irrelevant to which cipher a Schannel server
            // negotiates; a verifying connector would fail the handshake at cert
            // validation on bad-cert hosts and falsely report NotDetected.
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            match connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname, std_stream)
            {
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
                Err(_) => Ok(SchannelDetectionStatus::Inconclusive),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("Winshock blocking task failed: {}", e)))?
    }

    /// Test with malformed handshake that triggers Winshock
    async fn test_malformed_handshake(&self) -> Result<MalformedHandshakeStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let mut stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return Ok(MalformedHandshakeStatus::Inconclusive),
        };

        // Send normal ClientHello first
        let client_hello = client_hello::tls12_rsa()?;
        if client_hello.is_empty() {
            return Ok(MalformedHandshakeStatus::Inconclusive);
        }
        stream.write_all(&client_hello).await?;

        // Read the full ServerHello record so a fragmented handshake does not
        // get misclassified as inconclusive.
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        match read_io::complete_tls_record(&mut stream, &mut buffer, Duration::from_secs(3)).await {
            Ok(n) if n > 0 => {
                // Send malformed ClientKeyExchange that triggers Winshock
                let malformed_cke = messages::malformed_client_key_exchange();
                stream.write_all(&malformed_cke).await?;

                // Try to read response
                let mut response = vec![0u8; 1024];
                match read_io::complete_tls_record(
                    &mut stream,
                    &mut response,
                    Duration::from_secs(2),
                )
                .await
                {
                    Ok(n) if n > 0 => {
                        // Any server response (TLS alert 0x15 or other) means it handled
                        // the malformed CKE without crashing. TCP RST (below) is the
                        // primary Winshock indicator.
                        Ok(MalformedHandshakeStatus::Handled)
                    }
                    Ok(_) => {
                        // Empty response - connection closed without error
                        Ok(MalformedHandshakeStatus::Handled)
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        // A TCP reset after a deliberately malformed ClientKeyExchange
                        // is the NORMAL response of essentially every TLS stack
                        // (patched Schannel, OpenSSL, BoringSSL, nginx, IIS) and is
                        // also routinely produced by load balancers, IDS/IPS and rate
                        // limiters. It is indistinguishable from the Winshock crash
                        // signature at this layer, so it must NOT be asserted as a
                        // confirmed RCE — that false-positives every well-behaved
                        // server. Remote confirmation of CVE-2014-6321 is not feasible.
                        Ok(MalformedHandshakeStatus::Inconclusive)
                    }
                    Err(_) => Ok(MalformedHandshakeStatus::Inconclusive),
                }
            }
            _ => Ok(MalformedHandshakeStatus::Inconclusive),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BUFFER_SIZE_DEFAULT, CONTENT_TYPE_HANDSHAKE};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

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
        let malformed = messages::malformed_client_key_exchange();

        assert!(malformed.len() > 10);
        assert_eq!(malformed[0], 0x16); // Handshake record
        assert_eq!(malformed[5], 0x10); // ClientKeyExchange
    }

    #[test]
    fn test_client_hello_builder_structure() {
        let hello = client_hello::tls12_rsa().expect("ClientHello should build");

        assert!(hello.len() > 40);
        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[test]
    fn test_malformed_cke_contains_padding_pattern() {
        let malformed = messages::malformed_client_key_exchange();

        assert!(malformed.windows(4).any(|w| w == [0x41, 0x41, 0x41, 0x41]));
        assert!(malformed.len() >= 256);
    }

    #[test]
    fn test_malformed_cke_header_lengths() {
        let malformed = messages::malformed_client_key_exchange();

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
        let result = WinshockTestResult::from_probe_status(
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

    #[tokio::test]
    async fn test_winshock_tls_handshake_failure_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let tester = WinshockTester::new(target);
        let result = tester.test().await.unwrap();
        accept_task.await.unwrap();

        assert!(!result.vulnerable);
        assert!(!result.schannel_detected);
        assert!(result.inconclusive, "{result:?}");
        assert!(result.details.contains("inconclusive"), "{result:?}");
    }

    #[tokio::test]
    async fn test_winshock_read_complete_tls_record_handles_fragmented_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let response = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
            let _ = socket.write_all(&response[..2]).await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = socket.write_all(&response[2..]).await;
        });

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 32];
        let n = read_io::complete_tls_record(&mut stream, &mut buffer, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(n, 7);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_winshock_read_complete_tls_record_accepts_record_above_default_buffer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

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

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        let n = read_io::complete_tls_record(&mut stream, &mut buffer, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(n, 5 + BUFFER_SIZE_DEFAULT);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_winshock_read_complete_tls_record_rejects_oversized_record_for_buffer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(&[CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x20])
                .await
                .unwrap();
            socket.write_all(&[0u8; 8]).await.unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut buffer = [0u8; 16];
        let err = read_io::complete_tls_record(&mut stream, &mut buffer, Duration::from_secs(1))
            .await
            .expect_err("oversized record should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        server.await.unwrap();
    }
}
