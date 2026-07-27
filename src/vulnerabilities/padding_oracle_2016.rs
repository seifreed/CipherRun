// OpenSSL AES-NI Padding Oracle Vulnerability Test
// CVE-2016-2107
//
// OpenSSL 1.0.1 through 1.0.1t and 1.0.2 through 1.0.2h contain a padding oracle
// vulnerability when AES-NI (hardware acceleration) is enabled with CBC mode ciphers.
// The vulnerability allows a MITM attacker to decrypt HTTPS traffic through timing attacks.
//
// Detection strategy:
// 1. Identify if server supports AES-CBC cipher suites (not AES-GCM)
// 2. Establish a connection and send application data with invalid padding
// 3. Measure timing difference in server responses (alert vs normal processing)
// 4. Compare with valid padding timing to detect oracle
// 5. If consistent timing differences exist, the server is vulnerable

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;

mod result;

pub use result::PaddingOracle2016Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CbcSupportStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

impl CbcSupportStatus {
    fn merge(self, next: Self) -> Self {
        match (self, next) {
            (Self::Supported, _) | (_, Self::Supported) => Self::Supported,
            (Self::Inconclusive, _) | (_, Self::Inconclusive) => Self::Inconclusive,
            _ => Self::NotSupported,
        }
    }
}

fn classify_cbc_handshake_error(
    error: openssl::ssl::HandshakeError<std::net::TcpStream>,
) -> CbcSupportStatus {
    use openssl::ssl::{ErrorCode, HandshakeError};

    match error {
        HandshakeError::SetupFailure(_) | HandshakeError::WouldBlock(_) => {
            CbcSupportStatus::Inconclusive
        }
        HandshakeError::Failure(stream) => match stream.error().code() {
            ErrorCode::SYSCALL
            | ErrorCode::ZERO_RETURN
            | ErrorCode::WANT_READ
            | ErrorCode::WANT_WRITE => CbcSupportStatus::Inconclusive,
            _ => {
                let error = stream.error().to_string();
                classify_cbc_handshake_error_string(&error)
            }
        },
    }
}

fn classify_cbc_handshake_error_string(error: &str) -> CbcSupportStatus {
    if crate::utils::network::is_transport_anomaly_error(error) {
        CbcSupportStatus::Inconclusive
    } else {
        CbcSupportStatus::NotSupported
    }
}

/// Padding oracle timing analysis result
#[derive(Debug, Clone)]
pub struct PaddingOracleTimingResult {
    /// Average response time for valid padding (ms)
    pub valid_avg_ms: f64,
    /// Average response time for invalid padding (ms)
    pub invalid_avg_ms: f64,
    /// Whether a padding oracle was detected
    pub oracle_detected: bool,
    /// Whether the result is inconclusive (insufficient samples, high variance)
    pub inconclusive: bool,
    /// Details about the analysis
    pub details: String,
}

/// OpenSSL Padding Oracle 2016 vulnerability tester (CVE-2016-2107)
pub struct PaddingOracle2016Tester<'a> {
    target: &'a Target,
    connect_timeout: Duration,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

impl<'a> PaddingOracle2016Tester<'a> {
    /// Create new Padding Oracle 2016 tester
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before the padding-oracle probe.
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
        crate::utils::target_addrs::socket_addrs_for_probe(self.target, self.test_all_ips)
    }

    /// Connect, upgrading via STARTTLS first for plaintext-first services.
    async fn starttls_connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<tokio::net::TcpStream> {
        crate::utils::network::connect_with_starttls_target(
            addr,
            timeout,
            self.starttls,
            self.target,
            self.starttls_hostname.as_deref(),
            self.starttls_server_mode,
        )
        .await
    }

    /// Test for CVE-2016-2107 Padding Oracle vulnerability
    ///
    /// This vulnerability only affects:
    /// - OpenSSL 1.0.1 - 1.0.1t
    /// - OpenSSL 1.0.2 - 1.0.2h
    /// - When AES-NI (hardware acceleration) is enabled
    /// - With CBC mode ciphers (not GCM)
    pub async fn test(&self) -> Result<PaddingOracle2016Result> {
        // Step 1: Check if server supports AES-CBC ciphers
        let cbc_status = self.check_aes_cbc_support().await?;

        if cbc_status != CbcSupportStatus::Supported {
            return Ok(PaddingOracle2016Result::from_cbc_status(cbc_status));
        }

        // Step 2: Perform timing analysis to detect padding oracle
        let timing_result = self.perform_timing_analysis().await?;

        Ok(PaddingOracle2016Result::from_timing_result(timing_result))
    }

    /// Check if server supports AES-CBC cipher suites
    async fn check_aes_cbc_support(&self) -> Result<CbcSupportStatus> {
        let mut best = CbcSupportStatus::NotSupported;
        for addr in self.probe_addrs()? {
            best = best.merge(self.check_aes_cbc_support_addr(addr).await?);
            if best == CbcSupportStatus::Supported {
                break;
            }
        }
        Ok(best)
    }

    async fn check_aes_cbc_support_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<CbcSupportStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

        // AES-CBC cipher suites (explicitly exclude GCM which is AEAD)
        let aes_cbc_ciphers = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256";

        let stream = match self.starttls_connect(addr, self.connect_timeout).await {
            Ok(s) => s,
            Err(_) => return Ok(CbcSupportStatus::Inconclusive),
        };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, self.connect_timeout)?;

        let (hostname, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
        tokio::task::spawn_blocking(move || -> Result<CbcSupportStatus> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // Certificate validity is irrelevant to CBC cipher support; a verifying
            // connector would surface a "certificate verify failed" handshake error
            // that the classifier treats as NotSupported, false-negativing bad-cert
            // hosts.
            builder.set_verify(SslVerifyMode::NONE);

            // Set cipher list to only CBC mode
            builder.set_cipher_list(aes_cbc_ciphers)?;

            // Try TLS 1.0, 1.1, 1.2 (CVE affects these versions)
            if builder
                .set_min_proto_version(Some(SslVersion::TLS1))
                .is_err()
            {
                return Ok(CbcSupportStatus::Inconclusive);
            }
            if builder
                .set_max_proto_version(Some(SslVersion::TLS1_2))
                .is_err()
            {
                return Ok(CbcSupportStatus::Inconclusive);
            }

            let connector = builder.build();

            match connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname, std_stream)
            {
                Ok(_ssl_stream) => {
                    // Successfully connected with AES-CBC cipher
                    Ok(CbcSupportStatus::Supported)
                }
                Err(e) => Ok(classify_cbc_handshake_error(e)),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("Spawn blocking failed: {e}")))?
    }

    /// Perform timing analysis to detect padding oracle
    ///
    /// NOTE: This test is marked INCONCLUSIVE by design. A real CBC padding oracle
    /// test requires encrypting the crafted padding variants under the session keys
    /// negotiated during the TLS handshake. OpenSSL's Rust bindings do not expose
    /// session keys, so we cannot build properly encrypted CBC records. Sending
    /// plaintext bytes to the raw TCP stream after the handshake produces a malformed
    /// TLS record that any server rejects identically regardless of vulnerability.
    /// Manual testing with testssl.sh or a dedicated POODLE/padding oracle tool is
    /// required for a conclusive result.
    async fn perform_timing_analysis(&self) -> Result<PaddingOracleTimingResult> {
        Ok(PaddingOracleTimingResult {
            valid_avg_ms: 0.0,
            invalid_avg_ms: 0.0,
            oracle_detected: false,
            inconclusive: true,
            details: "CBC padding oracle timing test requires session key access to encrypt \
                      crafted padding variants. OpenSSL bindings do not expose session keys; \
                      unencrypted payloads are rejected identically by any server. \
                      Use testssl.sh or a dedicated tool for a conclusive result."
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::test_support::{spawn_dummy_server, two_ip_example_target};
    use std::net::IpAddr;

    #[test]
    fn test_padding_oracle_probe_addrs_honors_all_ips() {
        let target = two_ip_example_target(443);

        let first = PaddingOracle2016Tester::new(&target)
            .probe_addrs()
            .expect("test assertion should succeed");
        assert_eq!(first.len(), 1);

        let all = PaddingOracle2016Tester::new(&target)
            .with_test_all_ips(true)
            .probe_addrs()
            .expect("test assertion should succeed");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_padding_oracle_merge_preserves_inconclusive_status() {
        assert_eq!(
            CbcSupportStatus::NotSupported.merge(CbcSupportStatus::Inconclusive),
            CbcSupportStatus::Inconclusive
        );
        assert_eq!(
            CbcSupportStatus::Inconclusive.merge(CbcSupportStatus::Supported),
            CbcSupportStatus::Supported
        );
    }

    #[tokio::test]
    async fn test_padding_oracle_inactive_target_is_inconclusive() {
        let addr = spawn_dummy_server(1).await;
        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("test assertion should succeed");

        let tester = PaddingOracle2016Tester::new(&target);
        let result = tester.test().await.expect("test assertion should succeed");

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_padding_oracle_modern_server() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = PaddingOracle2016Tester::new(&target);

        let result = tester.test().await.expect("test assertion should succeed");

        // CVE-2016-2107 test is inconclusive by design (see perform_timing_analysis)
        assert!(!result.vulnerable);
        assert!(!result.timing_oracle_detected);
    }
}
