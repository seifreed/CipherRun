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
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::time::timeout;

mod replay;
mod result;
mod result_analysis;
mod status;

pub use result::{EarlyDataSizeInfo, EarlyDataTestResult, ReplayTestResult};
use status::{EarlyDataSupportStatus, Tls13SupportStatus};

/// 0-RTT / Early Data vulnerability tester
pub struct EarlyDataTester<'a> {
    target: &'a Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

impl<'a> EarlyDataTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before each 0-RTT probe.
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

    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    fn probe_addrs(&self) -> Result<Vec<std::net::SocketAddr>> {
        crate::utils::target_addrs::socket_addrs_for_probe(self.target, self.test_all_ips)
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

    /// Test for 0-RTT / Early Data replay vulnerability
    pub async fn test(&self) -> Result<EarlyDataTestResult> {
        // Test 1: Check if server supports early_data extension
        let early_data_support = self.test_early_data_support().await?;
        let supports_early_data = matches!(early_data_support, EarlyDataSupportStatus::Supported);

        if matches!(early_data_support, EarlyDataSupportStatus::Inconclusive) {
            return Ok(result_analysis::early_data_support_inconclusive());
        }

        if !supports_early_data {
            return Ok(result_analysis::early_data_not_supported());
        }

        // Test 2: Check max_early_data_size
        let early_data_info = self.get_max_early_data_size().await?;

        // Test 3: Attempt to replay 0-RTT data
        let replay_result = self.test_replay_attack().await?;

        Ok(result_analysis::supported_early_data_result(
            &early_data_info,
            &replay_result,
        ))
    }

    /// Test if the server accepts TLS 1.3 0-RTT / early data.
    async fn test_early_data_support(&self) -> Result<EarlyDataSupportStatus> {
        // TLS 1.3 connectivity is NOT equivalent to early_data support; the
        // server must issue an early-data-capable ticket and accept replayed
        // early data, which is exercised via session resumption.
        self.probe_zero_rtt_early_data().await
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

        // Determine real 0-RTT early-data acceptance via session resumption.
        let early_data_accepted = self.probe_zero_rtt_early_data().await?;

        if matches!(early_data_accepted, EarlyDataSupportStatus::Inconclusive) {
            return Ok(EarlyDataSizeInfo {
                tls13_supported: true,
                early_data_supported: false,
                max_early_data_size: None,
                is_estimated: false,
                inconclusive: true,
            });
        }

        if !matches!(early_data_accepted, EarlyDataSupportStatus::Supported) {
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

    /// Detect whether the server accepts TLS 1.3 0-RTT (early data).
    ///
    /// 0-RTT acceptance is signalled in the encrypted EncryptedExtensions and is
    /// only exercised on a *resumed* connection, so it cannot be read from a
    /// single cleartext ServerHello (the previous approach reported a false
    /// negative for every standard server). This performs the real test: a
    /// warm-up handshake plus request/response makes the server issue a
    /// NewSessionTicket into a shared resumption store, then a resumed handshake
    /// offers early data and checks whether the server accepted it via rustls'
    /// `is_early_data_accepted`.
    async fn probe_zero_rtt_early_data(&self) -> Result<EarlyDataSupportStatus> {
        let domain = match crate::utils::network::server_name_for_hostname(&self.target.hostname) {
            Ok(d) => d,
            Err(_) => return Ok(EarlyDataSupportStatus::Inconclusive),
        };

        // A scanner must be able to probe 0-RTT behaviour even on hosts with
        // expired/self-signed certificates (certificate validity is assessed
        // separately), so use the non-verifying connector — matching the rest of
        // the scanner's inspection paths.
        let mut config = crate::utils::insecure_tls::insecure_client_config();
        // Required for tokio-rustls to transmit early data on a resumed session.
        config.enable_early_data = true;
        let config = Arc::new(config);

        let addrs = match self.probe_addrs() {
            Ok(addrs) => addrs,
            Err(_) => return Ok(EarlyDataSupportStatus::Inconclusive),
        };

        let mut saw_not_supported = false;
        let mut saw_inconclusive = false;
        for addr in addrs {
            match self
                .probe_zero_rtt_early_data_on_addr(addr, &config, domain.clone())
                .await
            {
                EarlyDataSupportStatus::Supported => return Ok(EarlyDataSupportStatus::Supported),
                EarlyDataSupportStatus::NotSupported => saw_not_supported = true,
                EarlyDataSupportStatus::Inconclusive => saw_inconclusive = true,
            }
        }

        if saw_inconclusive {
            Ok(EarlyDataSupportStatus::Inconclusive)
        } else if saw_not_supported {
            Ok(EarlyDataSupportStatus::NotSupported)
        } else {
            Ok(EarlyDataSupportStatus::Inconclusive)
        }
    }

    async fn probe_zero_rtt_early_data_on_addr(
        &self,
        addr: std::net::SocketAddr,
        config: &Arc<ClientConfig>,
        domain: rustls::pki_types::ServerName<'static>,
    ) -> EarlyDataSupportStatus {
        // Warm-up: a full handshake plus a request/response exchange so the
        // server issues a NewSessionTicket, which rustls stores in the shared
        // resumption store. If this fails we cannot test 0-RTT — inconclusive.
        if self
            .warm_up_session(addr, config, domain.clone())
            .await
            .is_err()
        {
            return EarlyDataSupportStatus::Inconclusive;
        }

        self.probe_resumed_early_data(addr, config, domain).await
    }

    /// Establish a resumable session by completing a handshake and exchanging a
    /// request so the server delivers a NewSessionTicket.
    async fn warm_up_session(
        &self,
        addr: std::net::SocketAddr,
        config: &Arc<ClientConfig>,
        domain: rustls::pki_types::ServerName<'static>,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stream = self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await?;
        let connector = tokio_rustls::TlsConnector::from(config.clone());
        let request = self.minimal_http_request();

        timeout(TLS_HANDSHAKE_TIMEOUT, async {
            let mut tls = connector.connect(domain, stream).await?;
            tls.write_all(request.as_bytes()).await?;
            tls.flush().await?;
            // Read the response so rustls processes the NewSessionTicket and
            // stores it in the resumption store for the resumed probe.
            let mut buf = [0u8; 4096];
            let _ = tls.read(&mut buf).await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| crate::TlsError::Other("0-RTT warm-up handshake timed out".to_string()))?
        .map_err(|e| crate::TlsError::Other(format!("0-RTT warm-up handshake failed: {e}")))?;
        Ok(())
    }

    /// Resume the session offering 0-RTT early data and report whether the
    /// server accepted it.
    async fn probe_resumed_early_data(
        &self,
        addr: std::net::SocketAddr,
        config: &Arc<ClientConfig>,
        domain: rustls::pki_types::ServerName<'static>,
    ) -> EarlyDataSupportStatus {
        use tokio::io::AsyncWriteExt;

        let stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return EarlyDataSupportStatus::Inconclusive,
        };
        let connector = tokio_rustls::TlsConnector::from(config.clone()).early_data(true);
        let request = self.minimal_http_request();

        let accepted = timeout(TLS_HANDSHAKE_TIMEOUT, async {
            let mut tls = connector.connect(domain, stream).await?;
            // With early data enabled and a resumable ticket, this write is sent
            // as 0-RTT data before the handshake completes.
            tls.write_all(request.as_bytes()).await?;
            // flush() drives the handshake to completion (tokio-rustls finishes
            // the handshake on the write path while early data is buffered), so
            // 0-RTT acceptance is decided once it returns — no read required.
            tls.flush().await?;
            Ok::<bool, std::io::Error>(tls.get_ref().1.is_early_data_accepted())
        })
        .await;

        match accepted {
            Ok(Ok(true)) => EarlyDataSupportStatus::Supported,
            Ok(Ok(false)) => EarlyDataSupportStatus::NotSupported,
            _ => EarlyDataSupportStatus::Inconclusive,
        }
    }

    fn minimal_http_request(&self) -> String {
        format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.target.hostname
        )
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

        let domain = match crate::utils::network::server_name_for_hostname(&self.target.hostname) {
            Ok(domain) => domain,
            Err(_) => {
                return Ok(ReplayTestResult {
                    tested: false,
                    vulnerable: false,
                    inconclusive: true,
                    details: "Early Data replay test inconclusive - invalid TLS server name"
                        .to_string(),
                });
            }
        };
        let mut config = crate::utils::insecure_tls::insecure_client_config();
        config.enable_early_data = true;
        let config = Arc::new(config);

        let addrs = match self.probe_addrs() {
            Ok(addrs) => addrs,
            Err(_) => {
                return Ok(ReplayTestResult {
                    tested: false,
                    vulnerable: false,
                    inconclusive: true,
                    details: "Early Data replay test inconclusive - no socket addresses"
                        .to_string(),
                });
            }
        };

        let mut saw_inconclusive = false;
        for addr in addrs {
            if self
                .warm_up_session(addr, &config, domain.clone())
                .await
                .is_err()
            {
                saw_inconclusive = true;
                continue;
            }

            let first = self
                .probe_resumed_early_data(addr, &config, domain.clone())
                .await;
            let second = self
                .probe_resumed_early_data(addr, &config, domain.clone())
                .await;

            match (first, second) {
                (EarlyDataSupportStatus::Supported, EarlyDataSupportStatus::Supported)
                | (EarlyDataSupportStatus::Supported, EarlyDataSupportStatus::NotSupported)
                | (EarlyDataSupportStatus::NotSupported, _) => {
                    return Ok(replay::classify_pair(first, second));
                }
                _ => saw_inconclusive = true,
            }
        }

        if saw_inconclusive {
            Ok(replay::inconclusive_with_size(&early_data_info))
        } else {
            Ok(ReplayTestResult {
                tested: false,
                vulnerable: false,
                inconclusive: true,
                details: "Early Data replay test inconclusive - no probe result".to_string(),
            })
        }
    }

    /// Attempt to connect with TLS 1.3
    async fn connect_tls13(&self) -> Result<Tls13SupportStatus> {
        let addrs = self.probe_addrs()?;

        let domain = crate::utils::network::server_name_for_hostname(&self.target.hostname)?;
        let mut saw_not_supported = false;
        let mut saw_inconclusive = false;
        for addr in addrs {
            let stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
                Ok(s) => s,
                Err(_) => {
                    saw_inconclusive = true;
                    continue;
                }
            };

            // Certificate validity is assessed separately; use the non-verifying connector.
            let config = crate::utils::insecure_tls::insecure_client_config();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

            match timeout(
                TLS_HANDSHAKE_TIMEOUT,
                connector.connect(domain.clone(), stream),
            )
            .await
            {
                Ok(Ok(tls_stream)) => {
                    let (_, connection) = tls_stream.get_ref();
                    if connection.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3) {
                        return Ok(Tls13SupportStatus::Supported);
                    }
                    saw_not_supported = true;
                }
                Ok(Err(_)) | Err(_) => saw_inconclusive = true,
            }
        }

        if saw_inconclusive {
            Ok(Tls13SupportStatus::Inconclusive)
        } else if saw_not_supported {
            Ok(Tls13SupportStatus::NotSupported)
        } else {
            Ok(Tls13SupportStatus::Inconclusive)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Spawn a local TLS 1.3 server with the given early-data limit (0 disables
    /// 0-RTT). Returns the bound address; the server runs as a detached task.
    async fn spawn_tls13_server(max_early_data_size: u32) -> SocketAddr {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_config.max_early_data_size = max_early_data_size;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        if let Ok(mut tls) = acceptor.accept(stream).await {
                            // Consume the request (and any 0-RTT early data) and
                            // reply, so the session ticket flushes to the client.
                            let mut buf = [0u8; 1024];
                            let _ = tls.read(&mut buf).await;
                            let _ = tls
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                                .await;
                            let _ = tls.flush().await;
                        }
                    });
                }
            }
        });

        addr
    }

    fn localhost_target(addr: SocketAddr) -> Target {
        Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_probe_zero_rtt_without_early_data_reports_not_supported() {
        crate::utils::insecure_tls::ensure_ring_provider();
        let addr = spawn_tls13_server(0).await;
        let target = localhost_target(addr);

        let tester = EarlyDataTester::new(&target);
        let status = tester.probe_zero_rtt_early_data().await.unwrap();

        assert_eq!(status, EarlyDataSupportStatus::NotSupported);
    }

    #[tokio::test]
    async fn test_probe_zero_rtt_all_ips_uses_any_reachable_ip() {
        crate::utils::insecure_tls::ensure_ring_provider();
        let addr = spawn_tls13_server(16384).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 2]), addr.ip()],
        )
        .unwrap();

        let tester = EarlyDataTester::new(&target).with_test_all_ips(true);
        let status = tester.probe_zero_rtt_early_data().await.unwrap();

        assert_eq!(status, EarlyDataSupportStatus::Supported);
    }

    #[tokio::test]
    async fn test_probe_zero_rtt_with_early_data_reports_supported() {
        crate::utils::insecure_tls::ensure_ring_provider();
        let addr = spawn_tls13_server(16384).await;
        let target = localhost_target(addr);

        let tester = EarlyDataTester::new(&target);
        let status = tester.probe_zero_rtt_early_data().await.unwrap();

        assert_eq!(status, EarlyDataSupportStatus::Supported);
    }

    #[tokio::test]
    async fn test_early_data_full_flow_consistent_on_self_signed_tls13() {
        crate::utils::insecure_tls::ensure_ring_provider();
        // Self-signed cert (the common scanner case). connect_tls13 must use the
        // non-verifying connector, otherwise it false-reports "no TLS 1.3" and
        // contradicts the early-data support result.
        let addr = spawn_tls13_server(16384).await;
        let target = localhost_target(addr);

        let tester = EarlyDataTester::new(&target);
        let result = tester.test().await.unwrap();

        assert!(result.supports_early_data);
        // Internally consistent: early-data support implies a reported size.
        assert!(result.max_early_data_size.is_some());
    }

    #[tokio::test]
    async fn test_replay_attack_exercises_two_resumed_early_data_connections() {
        crate::utils::insecure_tls::ensure_ring_provider();
        let addr = spawn_tls13_server(16384).await;
        let target = localhost_target(addr);

        let tester = EarlyDataTester::new(&target);
        let result = tester.test_replay_attack().await.unwrap();

        assert!(result.tested || result.inconclusive);
        if result.tested {
            assert!(
                result.details.contains("0-RTT")
                    || result.details.contains("early data")
                    || result.details.contains("Early Data")
            );
        }
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
    async fn test_early_data_inactive_target_is_inconclusive() {
        crate::utils::insecure_tls::ensure_ring_provider();
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
        crate::utils::insecure_tls::ensure_ring_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.shutdown().await;
            }
        });

        let target = Target {
            hostname: "invalid..host".to_string(),
            port: addr.port(),
            ip_addresses: vec![IpAddr::from([127, 0, 0, 1])],
        };

        let tester = EarlyDataTester::new(&target);
        let err = tester.connect_tls13().await.unwrap_err();
        assert!(err.to_string().contains("Invalid DNS name"));
    }

    #[tokio::test]
    async fn test_connect_tls13_transport_anomaly_is_inconclusive() {
        crate::utils::insecure_tls::ensure_ring_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 512];
                let _ = socket.read(&mut buf).await;
            }
        });

        let target = localhost_target(addr);

        let tester = EarlyDataTester::new(&target);
        let status = tester.connect_tls13().await.unwrap();

        assert!(matches!(status, Tls13SupportStatus::Inconclusive));
    }

    #[tokio::test]
    async fn test_max_early_data_size_none_when_no_tls13() {
        crate::utils::insecure_tls::ensure_ring_provider();
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
