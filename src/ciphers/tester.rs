// Cipher tester façade. Public API, data contracts, configuration and tests stay here.

#[path = "tester/classification.rs"]
mod classification;
#[path = "tester/connection_pool.rs"]
mod connection_pool;
#[path = "tester/handshake_io.rs"]
mod handshake_io;
#[path = "tester/orchestration.rs"]
mod orchestration;
#[path = "tester/preference.rs"]
mod preference;
#[path = "tester/server_preference.rs"]
mod server_preference;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use super::{CipherStrength, CipherSuite};
use crate::Result;
use crate::constants::{
    BUFFER_SIZE_DEFAULT, CIPHER_TEST_READ_TIMEOUT, CONTENT_TYPE_HANDSHAKE, DEFAULT_CONNECT_TIMEOUT,
    HANDSHAKE_TYPE_SERVER_HELLO,
};
use crate::data::CIPHER_DB;
use crate::protocols::Protocol;
use crate::utils::adaptive::AdaptiveController;
use crate::utils::network::Target;
use connection_pool::TlsConnectionPool;
use preference::CipherPreferenceAnalyzer;

type CipherBatchResult = Vec<(CipherSuite, Result<(bool, Option<u64>)>)>;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherTestResult {
    pub cipher: CipherSuite,
    pub supported: bool,
    pub protocol: Protocol,
    pub server_preference: Option<usize>,
    pub handshake_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCipherSummary {
    pub protocol: Protocol,
    pub supported_ciphers: Vec<CipherSuite>,
    pub server_ordered: bool,
    pub server_preference: Vec<String>,
    pub preferred_cipher: Option<CipherSuite>,
    pub counts: CipherCounts,
    pub avg_handshake_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherCounts {
    pub total: usize,
    pub null_ciphers: usize,
    pub export_ciphers: usize,
    pub low_strength: usize,
    pub medium_strength: usize,
    pub high_strength: usize,
    pub forward_secrecy: usize,
    pub aead: usize,
}

pub struct CipherTester {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    test_all_ciphers: bool,
    sleep_duration: Option<Duration>,
    use_rdp: bool,
    starttls_protocol: Option<crate::starttls::StarttlsProtocol>,
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
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn dummy_target() -> Target {
        Target::with_ips(
            "example.test".to_string(),
            443,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed")
    }

    fn build_fake_server_hello(cipher: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x02);
        body.extend_from_slice(&[0x00, 0x00, 0x00]);
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
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

    async fn spawn_fake_tls_server(cipher: u16, accepts: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            let response = build_fake_server_hello(cipher);
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

    fn make_cipher(
        protocol: &str,
        hexcode: &str,
        key_exchange: &str,
        encryption: &str,
        bits: u16,
        export: bool,
    ) -> CipherSuite {
        CipherSuite {
            hexcode: hexcode.to_string(),
            openssl_name: format!("OPENSSL_{}", hexcode),
            iana_name: format!("IANA_{}", hexcode),
            protocol: protocol.to_string(),
            key_exchange: key_exchange.to_string(),
            authentication: "RSA".to_string(),
            encryption: encryption.to_string(),
            mac: "SHA256".to_string(),
            bits,
            export,
        }
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
            make_cipher("TLSv1.2", "0001", "RSA", "AES", 128, false),
            make_cipher("TLSv1.2", "0002", "RSA", "AES", 128, false),
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
        let tester = CipherTester::new(dummy_target());
        let tls13_cipher = make_cipher("TLSv1.3", "1301", "ECDHE", "AES_GCM", 128, false);
        let tls12_cipher = make_cipher("TLSv1.2", "003c", "RSA", "AES", 128, false);
        let sslv2_cipher = make_cipher("SSLv2", "0000", "RSA", "NULL", 0, false);

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
        let tester = CipherTester::new(dummy_target());
        let export_cipher = make_cipher("TLSv1.2", "0003", "RSA", "AES", 40, true);
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
        let addr = spawn_fake_tls_server(0xc02f, 1).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200));

        let chosen = tester
            .get_server_chosen_cipher(Protocol::TLS12, &[0xc02f, 0xc030])
            .await
            .expect("test assertion should succeed");

        assert_eq!(chosen, Some(0xc02f));
    }

    #[tokio::test]
    async fn test_determine_server_preference_fixed_choice() {
        let addr = spawn_fake_tls_server(0xc030, 3).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200));

        let ciphers = vec![
            make_cipher("TLSv1.2", "c030", "RSA", "AES", 256, false),
            make_cipher("TLSv1.2", "c02f", "RSA", "AES", 128, false),
            make_cipher("TLSv1.2", "c02b", "RSA", "AES", 128, false),
        ];

        let preference = tester
            .determine_server_preference(Protocol::TLS12, &ciphers)
            .await
            .expect("test assertion should succeed");

        assert_eq!(preference.first().map(String::as_str), Some("c030"));
        assert_eq!(preference.len(), ciphers.len());
    }

    #[tokio::test]
    async fn test_perform_cipher_handshake_success() {
        let addr = spawn_fake_tls_server(0xc02f, 1).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200));

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
    async fn test_perform_cipher_handshake_close_is_error_not_unsupported() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move { if let Ok((_socket, _)) = listener.accept().await {} });

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200));

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

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

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
    async fn test_protocol_ciphers_with_fake_server() {
        let addr = spawn_fake_tls_server(0xc02f, 200).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200))
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
        let accepts = CIPHER_DB.get_recommended_ciphers().len().saturating_add(5);
        let addr = spawn_fake_tls_server(0xc02f, accepts).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

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
        let addr = spawn_fake_tls_server(0xc02f, 600).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target)
            .with_connect_timeout(Duration::from_millis(200))
            .with_read_timeout(Duration::from_millis(200))
            .with_max_concurrent_tests(4)
            .with_connection_pool_size(0);

        let results = tester
            .test_all_protocols()
            .await
            .expect("test assertion should succeed");

        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_cipher_handshake_only_invalid_hexcode() {
        let addr = spawn_fake_tls_server(0xc02f, 1).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target should build");

        let tester = CipherTester::new(target);
        let mut cipher = make_cipher("TLSv1.2", "0001", "RSA", "AES", 128, false);
        cipher.hexcode = "ZZZZ".to_string();

        let (supported, time) = tester
            .test_cipher_handshake_only(&cipher, Protocol::TLS12, None)
            .await
            .expect("test assertion should succeed");

        assert!(!supported);
        assert!(time.is_none());
    }
}
