// 0-RTT / Early Data Replay Vulnerability Test
// TLS 1.3 0-RTT replay attacks
//
// TLS 1.3 allows 0-RTT (zero round-trip time) for faster reconnections,
// but this can enable replay attacks if the server doesn't implement
// proper anti-replay mechanisms.
//
// Attack vectors:
// - Replay of idempotent HTTP requests
// - Bypassing application-level replay protection
// - Duplicating sensitive operations
//
// References:
// - RFC 8446 Section 8 (TLS 1.3)
// - RFC 8470 (Using Early Data in HTTP)
// - OWASP: TLS 1.3 0-RTT Security Considerations

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::time::timeout;

/// Information about early data size from server
#[derive(Debug, Clone)]
pub struct EarlyDataSizeInfo {
    /// Whether TLS 1.3 is supported
    pub tls13_supported: bool,
    /// Whether early_data extension was advertised
    pub early_data_supported: bool,
    /// Maximum early data size in bytes (if known)
    pub max_early_data_size: Option<u32>,
    /// Whether the value was estimated (heuristic) vs actually parsed from ticket
    pub is_estimated: bool,
    /// Whether support could not be determined due to an operational failure
    pub inconclusive: bool,
}

/// Result of 0-RTT replay attack testing
#[derive(Debug, Clone)]
pub struct ReplayTestResult {
    /// Whether the test was actually performed
    pub tested: bool,
    /// Whether the server is vulnerable to replay
    pub vulnerable: bool,
    /// Whether the result is inconclusive (test could not be performed)
    pub inconclusive: bool,
    /// Details about the test result
    pub details: String,
}

/// 0-RTT / Early Data vulnerability tester
pub struct EarlyDataTester<'a> {
    target: &'a Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyDataSupportStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tls13SupportStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

impl<'a> EarlyDataTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self { target }
    }

    /// Test for 0-RTT / Early Data replay vulnerability
    pub async fn test(&self) -> Result<EarlyDataTestResult> {
        let mut issues = Vec::new();
        let mut vulnerable = false;

        // Test 1: Check if server supports early_data extension
        let early_data_support = self.test_early_data_support().await?;
        let supports_early_data = matches!(early_data_support, EarlyDataSupportStatus::Supported);

        if matches!(early_data_support, EarlyDataSupportStatus::Inconclusive) {
            return Ok(EarlyDataTestResult {
                vulnerable: false,
                supports_early_data: false,
                accepts_replayed_data: false,
                max_early_data_size: None,
                issues: vec![
                    "Early Data test inconclusive - unable to determine TLS 1.3 early_data support"
                        .to_string(),
                ],
                details:
                    "Early Data test inconclusive - target did not provide a usable TLS response"
                        .to_string(),
                inconclusive: true,
            });
        }

        if !supports_early_data {
            return Ok(EarlyDataTestResult {
                vulnerable: false,
                supports_early_data: false,
                accepts_replayed_data: false,
                max_early_data_size: None,
                issues: vec!["Server does not support TLS 1.3 early_data extension".to_string()],
                details: "Not vulnerable - Server does not support 0-RTT / early data".to_string(),
                inconclusive: false,
            });
        }

        issues.push("Server supports TLS 1.3 early_data extension (0x002a)".to_string());

        // Test 2: Check max_early_data_size
        let early_data_info = self.get_max_early_data_size().await?;
        if let Some(size) = early_data_info.max_early_data_size
            && size > 0
        {
            if early_data_info.is_estimated {
                issues.push(format!(
                    "Server likely accepts up to {} bytes of early data (estimated, actual value requires session ticket parsing)",
                    size
                ));
            } else {
                issues.push(format!("Server accepts up to {} bytes of early data", size));
            }
        }

        // Test 3: Attempt to replay 0-RTT data
        let replay_result = self.test_replay_attack().await?;

        if replay_result.inconclusive {
            issues.push(
                "⚠️ 0-RTT replay test is inconclusive - manual testing recommended".to_string(),
            );
            issues.push(replay_result.details.clone());
        } else if replay_result.vulnerable {
            vulnerable = true;
            issues.push(
                "⚠️ Server accepts replayed 0-RTT data without proper anti-replay protection"
                    .to_string(),
            );
            issues.push("This can allow replay attacks on sensitive operations".to_string());
        } else if replay_result.tested {
            issues.push("✓ Server appears to have anti-replay mechanisms in place".to_string());
        }

        let details = if vulnerable {
            format!(
                "Vulnerable to 0-RTT replay attacks - Server supports early_data and accepts replayed requests. \
                max_early_data_size: {}. Server should implement anti-replay mechanisms (single-use tickets, \
                time-based checks, or nonce tracking).",
                early_data_info
                    .max_early_data_size
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            )
        } else if replay_result.inconclusive {
            format!(
                "Inconclusive 0-RTT replay test - Server supports TLS 1.3 with early_data (max: {:?}). \
                Full replay testing was not performed. Potential vulnerability exists if server \
                lacks anti-replay mechanisms (single-use tickets, time-based checks, nonce tracking).",
                early_data_info.max_early_data_size
            )
        } else if supports_early_data {
            "Server supports 0-RTT but appears to have anti-replay protection enabled".to_string()
        } else {
            "Not vulnerable - Server does not support 0-RTT / early data".to_string()
        };

        Ok(EarlyDataTestResult {
            vulnerable,
            supports_early_data,
            accepts_replayed_data: replay_result.vulnerable,
            max_early_data_size: early_data_info.max_early_data_size,
            issues,
            details,
            inconclusive: replay_result.inconclusive,
        })
    }

    /// Test if server supports early_data extension (0x002a)
    async fn test_early_data_support(&self) -> Result<EarlyDataSupportStatus> {
        // TLS 1.3 connectivity is NOT equivalent to early_data support.
        // Actual detection requires parsing the early_data extension (0x002a) from
        // the NewSessionTicket message (RFC 8446 §4.6.1) — not yet implemented.
        self.check_early_data_extension_in_handshake().await
    }

    /// Get max_early_data_size from TLS 1.3 session ticket
    ///
    /// Note: This implementation checks if TLS 1.3 is supported and returns
    /// a conservative estimate. The actual max_early_data_size is encoded in
    /// the NewSessionTicket message's early_data extension (RFC 8446 Section 4.6.1).
    ///
    /// To get the exact value, one would need to:
    /// 1. Complete a full TLS 1.3 handshake
    /// 2. Receive and parse the NewSessionTicket message
    /// 3. Extract the max_early_data extension if present
    ///
    /// Common values observed in practice:
    /// - Cloudflare: 16384 bytes (16KB)
    /// - Google: varies by service
    /// - Apache/mod_ssl: typically 16384 bytes
    /// - Nginx: configurable, often 16384 bytes
    async fn get_max_early_data_size(&self) -> Result<EarlyDataSizeInfo> {
        match self.connect_tls13().await? {
            Tls13SupportStatus::Supported => {}
            Tls13SupportStatus::NotSupported => {
                return Ok(EarlyDataSizeInfo {
                    tls13_supported: false,
                    early_data_supported: false,
                    max_early_data_size: None,
                    is_estimated: false,
                    inconclusive: false,
                });
            }
            Tls13SupportStatus::Inconclusive => {
                return Ok(EarlyDataSizeInfo {
                    tls13_supported: false,
                    early_data_supported: false,
                    max_early_data_size: None,
                    is_estimated: false,
                    inconclusive: true,
                });
            }
        }

        // Check if server advertises early_data support in ServerHello
        // by checking for the presence of the early_data extension (type 0x002a)
        let early_data_in_server_hello = self.check_early_data_extension_in_handshake().await?;

        if matches!(
            early_data_in_server_hello,
            EarlyDataSupportStatus::Inconclusive
        ) {
            return Ok(EarlyDataSizeInfo {
                tls13_supported: true,
                early_data_supported: false,
                max_early_data_size: None,
                is_estimated: false,
                inconclusive: true,
            });
        }

        if !matches!(
            early_data_in_server_hello,
            EarlyDataSupportStatus::Supported
        ) {
            return Ok(EarlyDataSizeInfo {
                tls13_supported: true,
                early_data_supported: false,
                max_early_data_size: None,
                is_estimated: false,
                inconclusive: false,
            });
        }

        // If early_data is advertised, we return the most common value
        // This is a heuristic because parsing NewSessionTicket requires a full handshake
        // and handling of the session resumption flow
        Ok(EarlyDataSizeInfo {
            tls13_supported: true,
            early_data_supported: true,
            max_early_data_size: Some(16384), // Most common default
            is_estimated: true, // Mark as estimated since we didn't parse actual ticket
            inconclusive: false,
        })
    }

    /// Check if server hello contains early_data extension (0x002a)
    ///
    /// Sends a raw TLS 1.3 ClientHello offering early_data support and parses
    /// the ServerHello for extension 0x002a. Per RFC 8446, the definitive signal
    /// appears in EncryptedExtensions (which requires session keys to decrypt);
    /// this check catches non-standard servers that include it in the cleartext
    /// ServerHello. Standard TLS 1.3 servers will return false here.
    async fn check_early_data_extension_in_handshake(&self) -> Result<EarlyDataSupportStatus> {
        use crate::protocols::handshake::{ClientHelloBuilder, ServerHelloParser};
        use crate::protocols::{Extension, Protocol};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                Err(_) => return Ok(EarlyDataSupportStatus::Inconclusive),
            };

        let mut builder = ClientHelloBuilder::new(Protocol::TLS13);
        // Offer early_data (0x002a) in ClientHello so servers know we accept it.
        builder.add_extension(Extension::new(0x002a, vec![]));

        let hostname = &self.target.hostname;
        let client_hello = match builder.build_with_defaults(Some(hostname)) {
            Ok(ch) => ch,
            Err(_) => return Ok(EarlyDataSupportStatus::Inconclusive),
        };

        let response = match timeout(TLS_HANDSHAKE_TIMEOUT, async {
            stream.write_all(&client_hello).await?;
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await?;
            buf.truncate(n);
            Ok::<Vec<u8>, anyhow::Error>(buf)
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => return Ok(EarlyDataSupportStatus::Inconclusive),
        };

        match ServerHelloParser::parse(&response) {
            Ok(server_hello) => {
                if server_hello.has_extension(0x002a) {
                    Ok(EarlyDataSupportStatus::Supported)
                } else {
                    Ok(EarlyDataSupportStatus::NotSupported)
                }
            }
            Err(_) => Ok(EarlyDataSupportStatus::Inconclusive),
        }
    }

    /// Test replay attack by sending the same 0-RTT data twice
    ///
    /// NOTE: Full 0-RTT replay testing requires:
    /// 1. Establishing an initial TLS 1.3 connection
    /// 2. Receiving a NewSessionTicket with early_data extension
    /// 3. Reconnecting with 0-RTT data
    /// 4. Attempting to replay the same 0-RTT data
    ///
    /// This implementation marks results as INCONCLUSIVE when we cannot perform
    /// the full test, rather than returning false (not vulnerable) which would
    /// be misleading.
    async fn test_replay_attack(&self) -> Result<ReplayTestResult> {
        // First, check if TLS 1.3 is supported
        match self.connect_tls13().await? {
            Tls13SupportStatus::Supported => {}
            Tls13SupportStatus::NotSupported => {
                return Ok(ReplayTestResult {
                    tested: false,
                    vulnerable: false,
                    inconclusive: false,
                    details: "Server does not support TLS 1.3 - 0-RTT not applicable".to_string(),
                });
            }
            Tls13SupportStatus::Inconclusive => {
                return Ok(ReplayTestResult {
                    tested: false,
                    vulnerable: false,
                    inconclusive: true,
                    details:
                        "TLS 1.3 support inconclusive - 0-RTT replay test could not be performed"
                            .to_string(),
                });
            }
        }

        // Check if early_data extension is supported
        let early_data_info = self.get_max_early_data_size().await?;

        if early_data_info.inconclusive {
            return Ok(ReplayTestResult {
                tested: false,
                vulnerable: false,
                inconclusive: true,
                details: "Early Data support inconclusive - replay test could not be performed"
                    .to_string(),
            });
        }

        if !early_data_info.early_data_supported {
            return Ok(ReplayTestResult {
                tested: false,
                vulnerable: false,
                inconclusive: false,
                details: "Server does not advertise early_data support - 0-RTT not enabled"
                    .to_string(),
            });
        }

        // Full 0-RTT replay testing would require:
        // 1. Complete TLS 1.3 handshake to get session ticket
        // 2. Parse NewSessionTicket for max_early_data_size
        // 3. Resume connection with early data
        // 4. Attempt replay of same early data
        //
        // Since this requires significant TLS 1.3 state management,
        // we mark the result as INCONCLUSIVE with detailed explanation.
        // This is more honest than returning "not vulnerable" without testing.

        Ok(ReplayTestResult {
            tested: false,
            vulnerable: false,
            inconclusive: true,
            details: format!(
                "TLS 1.3 with early_data supported (max: {:?} bytes, estimated: {}). \
                 Full 0-RTT replay testing requires session resumption which is not \
                 currently implemented. Manual testing recommended. \
                 Potential vulnerability: Servers without anti-replay mechanisms may accept \
                 replayed 0-RTT data, allowing request duplication attacks.",
                early_data_info.max_early_data_size, early_data_info.is_estimated
            ),
        })
    }

    /// Attempt to connect with TLS 1.3
    async fn connect_tls13(&self) -> Result<Tls13SupportStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // Connect TCP
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(Tls13SupportStatus::Inconclusive),
            };

        // Build TLS 1.3 only config
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        // Try to connect
        let domain = crate::utils::network::server_name_for_hostname(&self.target.hostname)?;

        match timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(domain, stream)).await {
            Ok(Ok(tls_stream)) => {
                // Check if we got TLS 1.3
                let (_, connection) = tls_stream.get_ref();
                let protocol_version = connection.protocol_version();

                // rustls::ProtocolVersion::TLSv1_3 indicates TLS 1.3
                if protocol_version == Some(rustls::ProtocolVersion::TLSv1_3) {
                    Ok(Tls13SupportStatus::Supported)
                } else {
                    Ok(Tls13SupportStatus::NotSupported)
                }
            }
            Ok(Err(_)) => Ok(Tls13SupportStatus::NotSupported),
            Err(_) => Ok(Tls13SupportStatus::Inconclusive),
        }
    }
}

/// 0-RTT / Early Data test result
#[derive(Debug, Clone)]
pub struct EarlyDataTestResult {
    pub vulnerable: bool,
    pub supports_early_data: bool,
    pub accepts_replayed_data: bool,
    pub max_early_data_size: Option<u32>,
    pub issues: Vec<String>,
    pub details: String,
    pub inconclusive: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Once;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn fake_server_hello_without_early_data() -> Vec<u8> {
        let mut body = vec![0x02, 0x00, 0x00, 0x00, 0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x00);

        let hs_len = body.len() - 4;
        body[1] = ((hs_len >> 16) & 0xff) as u8;
        body[2] = ((hs_len >> 8) & 0xff) as u8;
        body[3] = (hs_len & 0xff) as u8;

        let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x00];
        let record_len = body.len();
        record[3] = ((record_len >> 8) & 0xff) as u8;
        record[4] = (record_len & 0xff) as u8;
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn test_early_data_result() {
        let result = EarlyDataTestResult {
            vulnerable: false,
            supports_early_data: true,
            accepts_replayed_data: false,
            max_early_data_size: Some(16384),
            issues: vec![],
            details: "Test".to_string(),
            inconclusive: false,
        };
        assert!(!result.vulnerable);
        assert!(result.supports_early_data);
    }

    #[tokio::test]
    async fn test_early_data_test_no_support() {
        install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(&fake_server_hello_without_early_data())
                    .await;
                let _ = socket.flush().await;
            }
        });

        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = EarlyDataTester::new(&target);
        let result = tester.test().await.unwrap();

        assert!(!result.supports_early_data);
        assert!(!result.vulnerable);
        assert!(result.issues.iter().any(|i| i.contains("does not support")));
    }

    #[tokio::test]
    async fn test_early_data_inactive_target_is_inconclusive() {
        install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = EarlyDataTester::new(&target);
        let result = tester.test().await.unwrap();

        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "inactive target must not be reported as a clean Early Data pass: {}",
            result.details
        );
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    #[tokio::test]
    async fn test_connect_tls13_invalid_hostname() {
        install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.shutdown().await;
            }
        });

        let target = Target::with_ips(
            "invalid..host".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = EarlyDataTester::new(&target);
        let err = tester.connect_tls13().await.unwrap_err();
        assert!(err.to_string().contains("Invalid DNS name"));
    }

    #[tokio::test]
    async fn test_max_early_data_size_none_when_no_tls13() {
        install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.shutdown().await;
            }
        });

        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = EarlyDataTester::new(&target);
        let info = tester
            .get_max_early_data_size()
            .await
            .expect("test assertion should succeed");
        assert!(!info.tls13_supported);
        assert!(info.max_early_data_size.is_none());
    }

    #[test]
    fn test_early_data_result_details() {
        let result = EarlyDataTestResult {
            supports_early_data: false,
            vulnerable: false,
            accepts_replayed_data: false,
            max_early_data_size: None,
            issues: vec![],
            details: "Not supported".to_string(),
            inconclusive: false,
        };
        assert!(result.details.contains("Not supported"));
    }

    #[test]
    fn test_early_data_result_issues_length() {
        let result = EarlyDataTestResult {
            supports_early_data: true,
            vulnerable: false,
            accepts_replayed_data: false,
            max_early_data_size: Some(1024),
            issues: vec!["Issue one".to_string(), "Issue two".to_string()],
            details: "Details".to_string(),
            inconclusive: false,
        };
        assert_eq!(result.issues.len(), 2);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_early_data_detection() {
        let target = Target::with_ips(
            "www.cloudflare.com".to_string(),
            443,
            vec!["104.16.132.229".parse().unwrap()],
        )
        .unwrap();

        let tester = EarlyDataTester::new(&target);
        let result = tester.test().await.expect("test assertion should succeed");

        // Cloudflare supports TLS 1.3
        assert!(result.supports_early_data || !result.vulnerable);
    }
}
