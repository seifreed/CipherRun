// Cipher tester façade. Public API, configuration and tests stay here.

#[path = "tester/classification.rs"]
mod classification;
#[path = "tester/connection_pool.rs"]
mod connection_pool;
#[path = "tester/handshake_io.rs"]
mod handshake_io;
#[path = "tester/model.rs"]
mod model;
#[path = "tester/orchestration.rs"]
mod orchestration;
#[path = "tester/preference.rs"]
mod preference;
#[path = "tester/server_preference.rs"]
mod server_preference;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use super::{CipherStrength, CipherSuite};
use crate::Result;
use crate::constants::{
    BUFFER_SIZE_MAX_WITH_OVERHEAD, CIPHER_TEST_READ_TIMEOUT, CONTENT_TYPE_HANDSHAKE,
    DEFAULT_CONNECT_TIMEOUT, HANDSHAKE_TYPE_SERVER_HELLO,
};
use crate::protocols::Protocol;
use crate::utils::adaptive::AdaptiveController;
use crate::utils::network::Target;
use connection_pool::TlsConnectionPool;
pub use model::{CipherCounts, CipherTestResult, ProtocolCipherSummary};
use preference::CipherPreferenceAnalyzer;

type CipherBatchResult = Vec<(CipherSuite, Result<(bool, Option<u64>)>)>;

#[cfg(test)]
mod test_support {
    use super::CipherSuite;

    pub(super) fn make_cipher(
        hexcode: &str,
        protocol: &str,
        encryption: &str,
        bits: u16,
        export: bool,
        key_exchange: &str,
    ) -> CipherSuite {
        CipherSuite {
            hexcode: hexcode.to_string(),
            openssl_name: format!("TEST-{}", hexcode),
            iana_name: format!("TLS_TEST_{}", hexcode),
            protocol: protocol.to_string(),
            key_exchange: key_exchange.to_string(),
            authentication: "RSA".to_string(),
            encryption: encryption.to_string(),
            mac: "SHA256".to_string(),
            bits,
            export,
        }
    }
}

#[async_trait::async_trait]
pub trait CipherTestable: Send + Sync {
    async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>>;
}

const BATCH_SIZE_MULTIPLIER: usize = 5;
const BACKOFF_BASE_DELAY_MS: u64 = 100;
const BACKOFF_MAX_EXPONENT: u32 = 4;
const RETRY_BACKOFF_SECS: u64 = 3;
const SERVER_HELLO_MIN_SIZE: usize = 44;
const SESSION_ID_LENGTH_OFFSET: usize = 43;
const CIPHER_SUITE_BASE_OFFSET: usize = 44;

pub struct CipherTester {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    test_all_ciphers: bool,
    sleep_duration: Option<Duration>,
    use_rdp: bool,
    starttls_protocol: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    sni_hostname: Option<String>,
    test_all_ips: bool,
    retry_config: Option<crate::utils::retry::RetryConfig>,
    max_concurrent_tests: usize,
    connection_pool_size: usize,
    adaptive: Option<Arc<AdaptiveController>>,
}

impl CipherTester {
    pub fn new(target: Target) -> Self {
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: CIPHER_TEST_READ_TIMEOUT,
            test_all_ciphers: false,
            sleep_duration: None,
            use_rdp,
            starttls_protocol: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            sni_hostname: None,
            test_all_ips: false,
            retry_config: None,
            max_concurrent_tests: 10,
            connection_pool_size: 10,
            adaptive: None,
        }
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn test_all(mut self, enable: bool) -> Self {
        self.test_all_ciphers = enable;
        self
    }

    pub fn with_sleep(mut self, duration: Duration) -> Self {
        self.sleep_duration = Some(duration);
        self
    }

    pub fn with_rdp(mut self, enable: bool) -> Self {
        self.use_rdp = enable;
        self
    }

    pub fn with_starttls(mut self, protocol: Option<crate::starttls::StarttlsProtocol>) -> Self {
        self.starttls_protocol = protocol;
        self
    }

    pub fn with_starttls_server_mode(mut self, server_mode: bool) -> Self {
        self.starttls_server_mode = server_mode;
        self
    }

    pub fn with_starttls_hostname(mut self, hostname: Option<String>) -> Self {
        self.starttls_hostname = hostname;
        self
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
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

    pub fn with_adaptive(mut self, adaptive: Option<Arc<AdaptiveController>>) -> Self {
        self.adaptive = adaptive;
        self
    }

    pub fn with_max_concurrent_tests(mut self, max: usize) -> Self {
        self.max_concurrent_tests = max.max(1);
        self
    }

    pub fn with_connection_pool_size(mut self, size: usize) -> Self {
        self.connection_pool_size = size;
        self
    }

    fn starttls_negotiation_hostname(&self) -> String {
        self.starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone())
    }
}

#[async_trait::async_trait]
impl CipherTestable for CipherTester {
    async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>> {
        self.test_all_protocols().await
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::make_cipher;
    use super::*;
    use crate::utils::test_support::{example_target, localhost_target};
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn local_cipher_tester(target: Target) -> CipherTester {
        CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200))
    }

    fn build_fake_server_hello(cipher: u16, session_id_len: usize) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x02);
        body.extend_from_slice(&[0x00, 0x00, 0x00]);
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(session_id_len as u8);
        body.extend(std::iter::repeat_n(0x41, session_id_len));
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x00]);

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

    async fn spawn_fake_tls_server(
        cipher: u16,
        session_id_len: usize,
        accepts: usize,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            let response = build_fake_server_hello(cipher, session_id_len);
            let mut remaining = accepts;
            while remaining > 0 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket.write_all(&response).await;
                    let _ = socket.flush().await;
                }
                remaining -= 1;
            }
        });

        addr
    }

    async fn spawn_fragmented_fake_tls_server(cipher: u16) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            let response = build_fake_server_hello(cipher, 0);
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(&response[..7]).await;
                let _ = socket.flush().await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                let _ = socket.write_all(&response[7..]).await;
                let _ = socket.flush().await;
            }
        });

        addr
    }

    #[test]
    fn test_cipher_preference_analyzer_client_preference() {
        let analyzer = CipherPreferenceAnalyzer::new(
            Some(0x0001),
            Some(0x0003),
            Some(0x0002),
            vec![0x0001, 0x0002, 0x0003],
            vec![0x0003, 0x0002, 0x0001],
            Some(vec![0x0002, 0x0003, 0x0001]),
        );

        assert!(analyzer.is_client_preference());
        assert!(!analyzer.is_server_preference());
        assert!(!analyzer.all_choices_same());
        assert!(!analyzer.mostly_same_different_positions());
    }

    #[test]
    fn test_cipher_preference_analyzer_server_preference() {
        let analyzer = CipherPreferenceAnalyzer::new(
            Some(0x0002),
            Some(0x0002),
            Some(0x0002),
            vec![0x0001, 0x0002, 0x0003],
            vec![0x0003, 0x0002, 0x0001],
            Some(vec![0x0002, 0x0003, 0x0001]),
        );

        assert!(analyzer.all_choices_same());
        assert!(analyzer.is_server_preference());
    }

    #[test]
    fn test_cipher_preference_analyzer_mixed_preference() {
        let analyzer = CipherPreferenceAnalyzer::new(
            Some(0x0001),
            Some(0x0002),
            Some(0x0002),
            vec![0x0001, 0x0002, 0x0003],
            vec![0x0003, 0x0002, 0x0001],
            Some(vec![0x0001, 0x0003, 0x0002]),
        );

        assert!(analyzer.mostly_same_different_positions());
        assert!(analyzer.is_server_preference());
    }

    #[test]
    fn test_cipher_preference_build_order() {
        let ciphers = vec![
            make_cipher("0001", "TLSv1.2", "AES", 128, false, "RSA"),
            make_cipher("0002", "TLSv1.2", "AES", 128, false, "RSA"),
        ];
        let analyzer = CipherPreferenceAnalyzer::new(
            Some(0x0002),
            None,
            None,
            vec![0x0001, 0x0002],
            vec![0x0002, 0x0001],
            None,
        );

        let order = analyzer.build_preference_order(&ciphers);
        assert_eq!(order.first().map(String::as_str), Some("0002"));
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn test_cipher_compatibility_and_counts() {
        let tester = CipherTester::new(example_target());
        let tls13_cipher = make_cipher("1301", "TLSv1.3", "AES_GCM", 128, false, "ECDHE");
        let tls12_cipher = make_cipher("003c", "TLSv1.2", "AES", 128, false, "RSA");
        let sslv2_cipher = make_cipher("0000", "SSLv2", "NULL", 0, false, "RSA");

        assert!(tester.is_cipher_compatible_with_protocol(&tls13_cipher, Protocol::TLS13));
        assert!(!tester.is_cipher_compatible_with_protocol(&tls12_cipher, Protocol::TLS13));
        assert!(tester.is_cipher_compatible_with_protocol(&sslv2_cipher, Protocol::SSLv2));
        assert!(!tester.is_cipher_compatible_with_protocol(&tls12_cipher, Protocol::SSLv2));
        assert!(tester.is_cipher_compatible_with_protocol(&tls12_cipher, Protocol::TLS12));
        assert!(!tester.is_cipher_compatible_with_protocol(&tls13_cipher, Protocol::TLS12));

        let counts = tester.calculate_cipher_counts(&[
            tls13_cipher.clone(),
            tls12_cipher.clone(),
            sslv2_cipher.clone(),
        ]);

        assert_eq!(counts.total, 3);
        assert_eq!(counts.null_ciphers, 1);
        assert_eq!(counts.export_ciphers, 0);
        assert_eq!(
            counts.low_strength + counts.medium_strength + counts.high_strength,
            2
        );
        assert!(counts.forward_secrecy >= 1);
        assert!(counts.aead >= 1);
    }

    #[test]
    fn test_cipher_counts_export_ciphers() {
        let tester = CipherTester::new(example_target());
        let export_cipher = make_cipher("0003", "TLSv1.2", "AES", 40, true, "RSA");
        let counts = tester.calculate_cipher_counts(&[export_cipher]);
        assert_eq!(counts.export_ciphers, 1);
    }

    #[tokio::test]
    #[ignore]
    async fn test_cipher_detection() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = CipherTester::new(target);

        let summary = tester
            .test_protocol_ciphers(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        assert!(!summary.supported_ciphers.is_empty());
        assert!(summary.counts.forward_secrecy > 0);
        assert_eq!(summary.counts.null_ciphers, 0);
        assert_eq!(summary.counts.export_ciphers, 0);
    }

    #[tokio::test]
    #[ignore]
    async fn test_server_preference() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = CipherTester::new(target);

        let summary = tester
            .test_protocol_ciphers(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        assert!(summary.server_ordered);
        assert!(!summary.server_preference.is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn test_quick_scan() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = CipherTester::new(target);

        let ciphers = tester
            .quick_test(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        assert!(!ciphers.is_empty());
    }

    #[test]
    fn test_cipher_strength_calculation() {
        let cipher = CipherSuite {
            hexcode: "c030".to_string(),
            openssl_name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            iana_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES256-GCM".to_string(),
            mac: "SHA384".to_string(),
            bits: 256,
            export: false,
        };

        assert_eq!(cipher.strength(), CipherStrength::High);
        assert!(cipher.has_forward_secrecy());
        assert!(cipher.is_aead());
    }

    #[tokio::test]
    async fn test_get_server_chosen_cipher_parses_response() {
        let addr = spawn_fake_tls_server(0xc02f, 0, 1).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target);

        let chosen = tester
            .get_server_chosen_cipher(Protocol::TLS12, &[0xc02f, 0xc030])
            .await
            .expect("test assertion should succeed");

        assert_eq!(chosen, Some(0xc02f));
    }

    #[cfg_attr(windows, ignore = "closed-port error semantics differ on Windows")]
    #[tokio::test]
    async fn test_get_server_chosen_cipher_propagates_connect_errors() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        drop(listener);

        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target);

        let err = tester
            .get_server_chosen_cipher(Protocol::TLS12, &[0xc02f, 0xc030])
            .await
            .expect_err("connection failure should not be reported as no chosen cipher");

        assert!(matches!(err, crate::TlsError::ConnectionRefused { .. }));
    }

    #[tokio::test]
    async fn test_get_server_chosen_cipher_propagates_parse_errors() {
        let addr = spawn_fake_tls_server(0xc02f, 33, 1).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target);

        let err = tester
            .get_server_chosen_cipher(Protocol::TLS12, &[0xc02f, 0xc030])
            .await
            .expect_err("malformed ServerHello should fail");
        assert!(
            err.to_string()
                .contains("Invalid ServerHello session_id_len")
        );
    }

    #[tokio::test]
    async fn test_determine_server_preference_fixed_choice() {
        let addr = spawn_fake_tls_server(0xc030, 0, 3).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target);

        let ciphers = vec![
            make_cipher("c030", "TLSv1.2", "AES", 256, false, "RSA"),
            make_cipher("c02f", "TLSv1.2", "AES", 128, false, "RSA"),
            make_cipher("c02b", "TLSv1.2", "AES", 128, false, "RSA"),
        ];

        let preference = tester
            .determine_server_preference(Protocol::TLS12, &ciphers)
            .await
            .expect("test assertion should succeed");

        assert_eq!(preference.first().map(String::as_str), Some("c030"));
        assert_eq!(preference.len(), ciphers.len());
    }

    #[tokio::test]
    async fn test_server_preference_honors_all_ips() {
        let addr = spawn_fake_tls_server(0xc030, 0, 1).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_test_all_ips(true)
            .with_connect_timeout(Duration::from_millis(100))
            .with_read_timeout(Duration::from_millis(200));

        let choice = tester
            .get_server_chosen_cipher(Protocol::TLS12, &[0xc02f, 0xc030])
            .await
            .expect("second IP should provide server choice");

        assert_eq!(choice, Some(0xc030));
    }

    #[tokio::test]
    async fn test_determine_server_preference_rejects_invalid_hexcode() {
        let tester = CipherTester::new(example_target());
        let ciphers = vec![make_cipher("not-hex", "TLSv1.2", "AES", 128, false, "RSA")];

        let error = tester
            .determine_server_preference(Protocol::TLS12, &ciphers)
            .await
            .expect_err("invalid cipher hexcode should fail");

        assert!(error.to_string().contains("Invalid cipher hexcode"));
    }

    #[tokio::test]
    async fn test_cipher_handshake_rejects_invalid_hexcode() {
        let tester = CipherTester::new(example_target());
        let cipher = make_cipher("not-hex", "TLSv1.2", "AES", 128, false, "RSA");

        let error = tester
            .test_cipher_handshake_only(&cipher, Protocol::TLS12, None)
            .await
            .expect_err("invalid cipher hexcode should fail");

        assert!(error.to_string().contains("Invalid cipher hexcode"));
    }

    #[tokio::test]
    async fn test_perform_cipher_handshake_success() {
        let addr = spawn_fake_tls_server(0xc02f, 0, 1).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target);

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");

        let ok = tester
            .perform_cipher_handshake(&mut stream, Protocol::TLS12, 0xc02f)
            .await
            .expect("test assertion should succeed");

        assert!(ok);
    }

    #[tokio::test]
    async fn test_perform_cipher_handshake_reads_fragmented_server_hello() {
        let addr = spawn_fragmented_fake_tls_server(0xc02f).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target);

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");

        let ok = tester
            .perform_cipher_handshake(&mut stream, Protocol::TLS12, 0xc02f)
            .await
            .expect("fragmented ServerHello should be read fully");

        assert!(ok);
    }

    #[tokio::test]
    async fn test_perform_cipher_handshake_close_is_error_not_unsupported() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move { if let Ok((_socket, _)) = listener.accept().await {} });

        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target);

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");

        let err = tester
            .perform_cipher_handshake(&mut stream, Protocol::TLS12, 0xc02f)
            .await
            .expect_err("connection close is inconclusive, not unsupported");

        assert!(!err.to_string().is_empty());
        assert!(!err.to_string().contains("unsupported"));
    }

    #[tokio::test]
    async fn test_try_cipher_handshake_closed_port_is_error() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        drop(listener);

        let target = localhost_target(addr.port());

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(100))
            .with_read_timeout(Duration::from_millis(100));

        let err = tester
            .try_cipher_handshake_on_ip(Protocol::TLS12, 0xc02f, addr)
            .await
            .expect_err("closed port should not be recorded as unsupported");

        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_all_ip_cipher_probe_is_inconclusive_when_any_ip_errors() {
        let rejecting = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let rejecting_addr = rejecting.local_addr().expect("local addr should exist");
        let server = tokio::spawn(async move {
            let (mut socket, _) = rejecting.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.expect("read ClientHello");
            socket
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
                .await
                .expect("write alert");
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            rejecting_addr.port(),
            vec![IpAddr::from([127, 0, 0, 1]), IpAddr::from([127, 0, 0, 2])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_test_all_ips(true)
            .with_connect_timeout(Duration::from_millis(100))
            .with_read_timeout(Duration::from_millis(100));

        let err = tester
            .try_cipher_handshake_all_ips(Protocol::TLS12, 0xc02f)
            .await
            .expect_err("mixed rejection/inconclusive must not be classified as unsupported");

        assert!(!err.to_string().is_empty());
        server.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn test_protocol_ciphers_with_fake_server() {
        let addr = spawn_fake_tls_server(0xc02f, 0, 200).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target)
            .with_max_concurrent_tests(4)
            .with_connection_pool_size(0);

        let summary = tester
            .test_protocol_ciphers(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        assert!(!summary.supported_ciphers.is_empty());
        assert!(summary.counts.total > 0);
    }

    #[tokio::test]
    async fn test_quick_test_with_fake_server() {
        let accepts = crate::data::cipher_db()
            .expect("embedded cipher database should load")
            .get_recommended_ciphers()
            .len()
            .saturating_add(5);
        let addr = spawn_fake_tls_server(0xc02f, 0, accepts).await;
        let target = localhost_target(addr.port());

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(400))
            .with_read_timeout(Duration::from_millis(400));

        let mut last_err = None;
        let mut last_empty = false;
        for _ in 0..3 {
            match tester.quick_test(Protocol::TLS12).await {
                Ok(ciphers) => {
                    if !ciphers.is_empty() {
                        return;
                    }
                    last_empty = true;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => {
                    last_err = Some(err);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }

        if last_empty {
            panic!("test assertion should succeed: empty cipher list");
        } else {
            panic!("test assertion should succeed: {:?}", last_err);
        }
    }

    #[tokio::test]
    async fn test_all_protocols_with_fake_server() {
        let addr = spawn_fake_tls_server(0xc02f, 0, 600).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target)
            .with_max_concurrent_tests(4)
            .with_connection_pool_size(0);

        let results = tester
            .test_all_protocols()
            .await
            .expect("test assertion should succeed");

        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_all_protocols_all_ciphers_does_not_error_on_sslv2_kind_values() {
        // Regression: with `test_all(true)` the cipher DB includes SSLv2 suites
        // whose 24-bit "kind" hexcodes (e.g. 0x060040) do not fit a u16. The TLS
        // ClientHello cipher list is 16-bit, so those suites are not TLS-offerable
        // and must be skipped (not errored) — otherwise full cipher enumeration
        // (`--each-cipher` / `test_all_protocols`) aborted with
        // "Invalid cipher hexcode '060040': number too large to fit in target type".
        let addr = spawn_fake_tls_server(0xc02f, 0, 600).await;
        let target = localhost_target(addr.port());

        let tester = local_cipher_tester(target)
            .test_all(true)
            .with_max_concurrent_tests(4)
            .with_connection_pool_size(0);

        let results = tester
            .test_all_protocols()
            .await
            .expect("all-ciphers enumeration must not abort on SSLv2 kind values");

        // The fake server answers every TLS probe with a ServerHello, so at
        // least one TLS protocol must report supported ciphers.
        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_cipher_handshake_only_invalid_hexcode() {
        let tester = CipherTester::new(example_target());
        let mut cipher = make_cipher("0001", "TLSv1.2", "AES", 128, false, "RSA");
        cipher.hexcode = "ZZZZ".to_string();

        let error = tester
            .test_cipher_handshake_only(&cipher, Protocol::TLS12, None)
            .await
            .expect_err("invalid cipher hexcode should fail");

        assert!(error.to_string().contains("Invalid cipher hexcode"));
    }
}
