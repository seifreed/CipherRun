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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CbcSupportStatus {
    Supported,
    NotSupported,
    Inconclusive,
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
    let error = error.to_ascii_lowercase();
    if error.contains("unexpected eof")
        || error.contains("connection reset")
        || error.contains("reset by peer")
        || error.contains("connection refused")
        || error.contains("timed out")
        || error.contains("timeout")
        || error.contains("closed")
        || error.contains("no protocols available")
        || error.contains("shutdown while in init")
        || error.contains("errno=54")
    {
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
}

impl<'a> PaddingOracle2016Tester<'a> {
    /// Create new Padding Oracle 2016 tester
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
        }
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
        let cbc_supported = cbc_status == CbcSupportStatus::Supported;

        if cbc_status == CbcSupportStatus::Inconclusive {
            return Ok(PaddingOracle2016Result {
                vulnerable: false,
                inconclusive: true,
                cbc_supported: false,
                timing_oracle_detected: false,
                details:
                    "INCONCLUSIVE: unable to determine AES-CBC cipher support for CVE-2016-2107"
                        .to_string(),
                average_valid_timing_ms: 0.0,
                average_invalid_timing_ms: 0.0,
            });
        }

        if cbc_status == CbcSupportStatus::NotSupported {
            return Ok(PaddingOracle2016Result {
                vulnerable: false,
                inconclusive: false,
                cbc_supported: false,
                timing_oracle_detected: false,
                details: "Server does not support AES-CBC cipher suites (only GCM/other AEAD)"
                    .to_string(),
                average_valid_timing_ms: 0.0,
                average_invalid_timing_ms: 0.0,
            });
        }

        // Step 2: Perform timing analysis to detect padding oracle
        let timing_result = self.perform_timing_analysis().await?;

        let vulnerable = cbc_supported && timing_result.oracle_detected;

        let details = if timing_result.inconclusive {
            format!(
                "INCONCLUSIVE: AES-CBC supported but timing analysis uncertain. {}. \
                 Manual testing recommended as padding oracle may exist.",
                timing_result.details
            )
        } else if vulnerable {
            format!(
                "VULNERABLE to CVE-2016-2107 Padding Oracle - Timing difference detected: valid={:.2}ms, invalid={:.2}ms. {}",
                timing_result.valid_avg_ms, timing_result.invalid_avg_ms, timing_result.details
            )
        } else if cbc_supported {
            format!(
                "AES-CBC supported but no clear timing oracle detected - valid={:.2}ms, invalid={:.2}ms. {}",
                timing_result.valid_avg_ms, timing_result.invalid_avg_ms, timing_result.details
            )
        } else {
            "Not vulnerable - AES-CBC not supported".to_string()
        };

        Ok(PaddingOracle2016Result {
            vulnerable,
            inconclusive: timing_result.inconclusive,
            cbc_supported,
            timing_oracle_detected: timing_result.oracle_detected,
            details,
            average_valid_timing_ms: timing_result.valid_avg_ms,
            average_invalid_timing_ms: timing_result.invalid_avg_ms,
        })
    }

    /// Check if server supports AES-CBC cipher suites
    async fn check_aes_cbc_support(&self) -> Result<CbcSupportStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // AES-CBC cipher suites (explicitly exclude GCM which is AEAD)
        let aes_cbc_ciphers = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256";

        let stream =
            match crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(CbcSupportStatus::Inconclusive),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, self.connect_timeout)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

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

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_ssl_stream) => {
                // Successfully connected with AES-CBC cipher
                Ok(CbcSupportStatus::Supported)
            }
            Err(e) => Ok(classify_cbc_handshake_error(e)),
        }
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

/// Padding Oracle 2016 test result
#[derive(Debug, Clone)]
pub struct PaddingOracle2016Result {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub cbc_supported: bool,
    pub timing_oracle_detected: bool,
    pub details: String,
    pub average_valid_timing_ms: f64,
    pub average_invalid_timing_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use tokio::net::TcpListener;

    #[test]
    fn test_result_structure() {
        let result = PaddingOracle2016Result {
            vulnerable: true,
            inconclusive: false,
            cbc_supported: true,
            timing_oracle_detected: true,
            details: "Test vulnerability detected".to_string(),
            average_valid_timing_ms: 15.5,
            average_invalid_timing_ms: 5.2,
        };

        assert!(result.vulnerable);
        assert!(result.cbc_supported);
        assert!(result.timing_oracle_detected);
        assert!(result.average_valid_timing_ms > result.average_invalid_timing_ms);
    }

    #[test]
    fn test_result_debug_contains_details() {
        let result = PaddingOracle2016Result {
            vulnerable: false,
            inconclusive: false,
            cbc_supported: false,
            timing_oracle_detected: false,
            details: "No oracle detected".to_string(),
            average_valid_timing_ms: 0.0,
            average_invalid_timing_ms: 0.0,
        };

        let debug = format!("{:?}", result);
        assert!(debug.contains("No oracle detected"));
    }

    #[test]
    fn test_result_not_vulnerable_fields() {
        let result = PaddingOracle2016Result {
            vulnerable: false,
            inconclusive: false,
            cbc_supported: false,
            timing_oracle_detected: false,
            details: "Not vulnerable".to_string(),
            average_valid_timing_ms: 0.0,
            average_invalid_timing_ms: 0.0,
        };

        assert!(!result.vulnerable);
        assert!(!result.cbc_supported);
        assert!(!result.timing_oracle_detected);
    }

    #[test]
    fn test_result_details_contains_not_vulnerable() {
        let result = PaddingOracle2016Result {
            vulnerable: false,
            inconclusive: false,
            cbc_supported: false,
            timing_oracle_detected: false,
            details: "Not vulnerable - CBC ciphers not supported".to_string(),
            average_valid_timing_ms: 0.0,
            average_invalid_timing_ms: 0.0,
        };
        assert!(result.details.contains("Not vulnerable"));
    }

    async fn spawn_dummy_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_padding_oracle_inactive_target_is_inconclusive() {
        let addr = spawn_dummy_server().await;
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
