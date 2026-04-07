// Protocol tester façade. Public API, configuration and tests stay here.

#[path = "tester/feature_detection.rs"]
mod feature_detection;
#[path = "tester/probing.rs"]
mod probing;

use super::{Protocol, ProtocolTestResult};
use crate::Result;
use crate::constants::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT};
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use std::time::Duration;

#[async_trait::async_trait]
pub trait ProtocolTestable: Send + Sync {
    async fn test_all_protocols(&self) -> Result<Vec<ProtocolTestResult>>;
    async fn test_protocol(&self, protocol: Protocol) -> Result<ProtocolTestResult>;
}

pub struct ProtocolTester {
    pub(super) target: Target,
    pub(super) connect_timeout: Duration,
    pub(super) read_timeout: Duration,
    pub(super) mtls_config: Option<MtlsConfig>,
    pub(super) use_rdp: bool,
    pub(super) enable_bugs_mode: bool,
    pub(super) starttls_protocol: Option<crate::starttls::StarttlsProtocol>,
    pub(super) sni_hostname: Option<String>,
    pub(super) protocol_filter: Option<Vec<Protocol>>,
    pub(super) test_all_ips: bool,
    pub(super) retry_config: Option<crate::utils::retry::RetryConfig>,
}

impl ProtocolTester {
    pub fn new(target: Target) -> Self {
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            mtls_config: None,
            use_rdp,
            enable_bugs_mode: false,
            starttls_protocol: None,
            sni_hostname: None,
            protocol_filter: None,
            test_all_ips: false,
            retry_config: None,
        }
    }

    pub fn with_mtls(target: Target, mtls_config: MtlsConfig) -> Self {
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            mtls_config: Some(mtls_config),
            use_rdp,
            enable_bugs_mode: false,
            starttls_protocol: None,
            sni_hostname: None,
            protocol_filter: None,
            test_all_ips: false,
            retry_config: None,
        }
    }

    pub fn with_bugs_mode(mut self, enable: bool) -> Self {
        self.enable_bugs_mode = enable;
        self
    }

    pub fn with_starttls(mut self, protocol: Option<crate::starttls::StarttlsProtocol>) -> Self {
        self.starttls_protocol = protocol;
        self
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    pub fn with_protocol_filter(mut self, protocols: Option<Vec<Protocol>>) -> Self {
        self.protocol_filter = protocols;
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn with_rdp(mut self, enable: bool) -> Self {
        self.use_rdp = enable;
        self
    }

    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    pub fn with_retry_config(mut self, config: Option<crate::utils::retry::RetryConfig>) -> Self {
        self.retry_config = config;
        self
    }

    pub async fn get_preferred_protocol(&self) -> Result<Option<Protocol>> {
        let results = self.test_all_protocols().await?;

        for protocol in [
            Protocol::TLS13,
            Protocol::TLS12,
            Protocol::TLS11,
            Protocol::TLS10,
            Protocol::SSLv3,
            Protocol::SSLv2,
        ] {
            if results
                .iter()
                .any(|r| r.protocol == protocol && r.supported)
            {
                return Ok(Some(protocol));
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl ProtocolTestable for ProtocolTester {
    async fn test_all_protocols(&self) -> Result<Vec<ProtocolTestResult>> {
        self.test_all_protocols().await
    }

    async fn test_protocol(&self, protocol: Protocol) -> Result<ProtocolTestResult> {
        self.test_protocol(protocol).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn dummy_target() -> Target {
        Target::with_ips(
            "example.test".to_string(),
            443,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed")
    }

    #[test]
    fn test_build_sslv2_client_hello_structure() {
        let tester = ProtocolTester::new(dummy_target());
        let hello = tester.build_sslv2_client_hello();

        assert_eq!(hello[0] & 0x80, 0x80);
        assert_eq!(hello[2], 0x01);
        assert_eq!(hello[3], 0x00);
        assert_eq!(hello[4], 0x02);
        assert!(hello.len() >= 6 + 3 * 3 + 16);
    }

    #[tokio::test]
    async fn test_quic_unimplemented_returns_false() {
        let tester = ProtocolTester::new(dummy_target());
        let addr = tester.target.socket_addrs()[0];
        let supported = tester
            .test_quic_on_ip(addr)
            .await
            .expect("test assertion should succeed");
        assert!(!supported);
    }

    #[test]
    fn test_setters_update_config() {
        let tester = ProtocolTester::new(dummy_target())
            .with_bugs_mode(true)
            .with_sni(Some("custom.test".to_string()))
            .with_protocol_filter(Some(vec![Protocol::TLS13]));

        assert!(tester.enable_bugs_mode);
        assert_eq!(tester.sni_hostname.as_deref(), Some("custom.test"));
        assert!(matches!(tester.protocol_filter, Some(ref p) if p == &[Protocol::TLS13]));
    }

    #[test]
    fn test_default_config_flags() {
        let tester = ProtocolTester::new(dummy_target());
        assert!(!tester.enable_bugs_mode);
        assert!(tester.sni_hostname.is_none());
        assert!(tester.protocol_filter.is_none());
    }

    #[test]
    fn test_additional_setters_update_config() {
        let retry = crate::utils::retry::RetryConfig::default();
        let tester = ProtocolTester::new(dummy_target())
            .with_connect_timeout(Duration::from_secs(3))
            .with_read_timeout(Duration::from_secs(4))
            .with_rdp(true)
            .with_test_all_ips(true)
            .with_retry_config(Some(retry.clone()))
            .with_starttls(Some(crate::starttls::StarttlsProtocol::SMTP));

        assert_eq!(tester.connect_timeout, Duration::from_secs(3));
        assert_eq!(tester.read_timeout, Duration::from_secs(4));
        assert!(tester.use_rdp);
        assert!(tester.test_all_ips);
        assert!(tester.retry_config.is_some());
        assert_eq!(
            tester.starttls_protocol,
            Some(crate::starttls::StarttlsProtocol::SMTP)
        );
    }

    #[test]
    fn test_with_mtls_sets_config() {
        let cert = CertificateDer::from(vec![0x01, 0x02, 0x03]);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x04, 0x05, 0x06]));
        let mtls = MtlsConfig {
            cert_chain: vec![cert],
            private_key: key,
        };

        let tester = ProtocolTester::with_mtls(dummy_target(), mtls);
        assert!(tester.mtls_config.is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn test_protocol_detection() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = ProtocolTester::new(target);

        let results = tester
            .test_all_protocols()
            .await
            .expect("test assertion should succeed");

        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::TLS12 && r.supported)
        );
        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::TLS13 && r.supported)
        );
        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::SSLv2 && !r.supported)
        );
        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::SSLv3 && !r.supported)
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_preferred_protocol() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = ProtocolTester::new(target);

        let preferred = tester
            .get_preferred_protocol()
            .await
            .expect("test assertion should succeed");

        assert_eq!(preferred, Some(Protocol::TLS13));
    }

    #[test]
    fn test_sslv2_client_hello_build() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().expect("valid IP")],
        )
        .expect("target should build");

        let tester = ProtocolTester::new(target);
        let hello = tester.build_sslv2_client_hello();

        assert!(hello.len() > 30);
        assert_eq!(hello[0], 0x80);
        assert_eq!(hello[2], 0x01);
    }

    async fn spawn_sslv2_dummy_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(&[0x80, 0x02, 0x04]).await;
                let _ = stream.flush().await;
            }
        });

        addr
    }

    async fn spawn_close_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move { if let Ok((_stream, _)) = listener.accept().await {} });

        addr
    }

    #[tokio::test]
    async fn test_sslv2_protocol_success_with_dummy_server() {
        let addr = spawn_sslv2_dummy_server().await;
        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = ProtocolTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200));

        let result = tester
            .test_protocol(Protocol::SSLv2)
            .await
            .expect("test assertion should succeed");

        assert!(result.supported);
    }

    #[tokio::test]
    async fn test_test_all_ips_returns_false_on_inconsistent_support() {
        let addr = spawn_sslv2_dummy_server().await;
        let target = Target::with_ips(
            "example.test".to_string(),
            addr.port(),
            vec![addr.ip(), "127.0.0.2".parse().expect("valid IP")],
        )
        .expect("target should build");
        let tester = ProtocolTester::new(target)
            .with_test_all_ips(true)
            .with_connect_timeout(Duration::from_millis(100))
            .with_read_timeout(Duration::from_millis(100));

        let result = tester
            .test_protocol(Protocol::SSLv2)
            .await
            .expect("test assertion should succeed");

        assert!(!result.supported);
    }

    #[tokio::test]
    async fn test_detect_heartbeat_extension_returns_false_on_close() {
        let addr = spawn_close_server().await;
        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = ProtocolTester::new(target)
            .with_connect_timeout(Duration::from_millis(100))
            .with_read_timeout(Duration::from_millis(100));

        let supported = tester
            .detect_heartbeat_extension(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        assert!(!supported);
    }
}
