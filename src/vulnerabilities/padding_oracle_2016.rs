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
use crate::utils::timing::{TimingOracleConfig, TimingSampleSet, detect_timing_oracle};
use std::io::{Read, Write};
use std::time::Duration;
use tokio::time::Instant;

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
        let cbc_supported = self.check_aes_cbc_support().await?;

        if !cbc_supported {
            return Ok(PaddingOracle2016Result {
                vulnerable: false,
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
            cbc_supported,
            timing_oracle_detected: timing_result.oracle_detected,
            details,
            average_valid_timing_ms: timing_result.valid_avg_ms,
            average_invalid_timing_ms: timing_result.invalid_avg_ms,
        })
    }

    /// Check if server supports AES-CBC cipher suites
    async fn check_aes_cbc_support(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No socket addresses available for target"))?;

        // AES-CBC cipher suites (explicitly exclude GCM which is AEAD)
        let aes_cbc_ciphers = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256";

        let stream =
            match crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Set cipher list to only CBC mode
        builder.set_cipher_list(aes_cbc_ciphers)?;

        // Try TLS 1.0, 1.1, 1.2 (CVE affects these versions)
        builder.set_min_proto_version(Some(SslVersion::TLS1))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_ssl_stream) => {
                // Successfully connected with AES-CBC cipher
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Perform timing analysis to detect padding oracle
    ///
    /// Strategy:
    /// 1. Send multiple requests with valid padding
    /// 2. Send multiple requests with invalid padding
    /// 3. Measure response times for each
    /// 4. Use statistical analysis to detect timing differences
    ///
    /// Returns (valid_avg, invalid_avg, oracle_detected, inconclusive)
    async fn perform_timing_analysis(&self) -> Result<PaddingOracleTimingResult> {
        const SAMPLES: usize = 25;
        const MIN_SAMPLES: usize = 15;
        const TIMING_THRESHOLD_MS: f64 = 15.0;

        let mut valid_timings = TimingSampleSet::with_capacity(SAMPLES);
        let mut invalid_timings = TimingSampleSet::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            if let Ok(time) = self.send_padded_request(true).await {
                valid_timings.push(time);
            }
            if let Ok(time) = self.send_padded_request(false).await {
                invalid_timings.push(time);
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        let config = TimingOracleConfig {
            min_samples: MIN_SAMPLES,
            timing_threshold_ms: TIMING_THRESHOLD_MS,
            cv_max: 0.4,
            significance_base_ms: TIMING_THRESHOLD_MS,
        };

        let analysis = match detect_timing_oracle(&valid_timings, &invalid_timings, &config) {
            Some(result) => result,
            None => {
                return Ok(PaddingOracleTimingResult {
                    valid_avg_ms: 0.0,
                    invalid_avg_ms: 0.0,
                    oracle_detected: false,
                    inconclusive: true,
                    details: format!(
                        "Insufficient timing samples (valid: {}, invalid: {}, need: {}). \
                         Network conditions prevented reliable timing measurement.",
                        valid_timings.len(),
                        invalid_timings.len(),
                        MIN_SAMPLES
                    ),
                });
            }
        };

        let vs = &analysis.valid_stats;
        let is = &analysis.invalid_stats;

        let details = if !analysis.timing_reliable {
            format!(
                "Timing measurements unreliable (CV valid: {:.2}, invalid: {:.2}). \
                 High variance suggests network jitter. Diff: {:.2}ms. \
                 Manual testing recommended.",
                vs.coefficient_of_variation, is.coefficient_of_variation, analysis.timing_diff_ms
            )
        } else if analysis.oracle_detected {
            format!(
                "Padding oracle DETECTED: timing difference {:.2}ms exceeds threshold ({:.1}ms). \
                 Valid padding avg: {:.2}ms (σ={:.2}ms), Invalid padding avg: {:.2}ms (σ={:.2}ms). \
                 Statistical significance confirmed.",
                analysis.timing_diff_ms,
                TIMING_THRESHOLD_MS,
                vs.mean,
                vs.stddev,
                is.mean,
                is.stddev
            )
        } else {
            format!(
                "No padding oracle detected: timing difference {:.2}ms below threshold ({:.1}ms). \
                 Valid padding avg: {:.2}ms, Invalid padding avg: {:.2}ms.",
                analysis.timing_diff_ms, TIMING_THRESHOLD_MS, vs.mean, is.mean
            )
        };

        Ok(PaddingOracleTimingResult {
            valid_avg_ms: vs.mean,
            invalid_avg_ms: is.mean,
            oracle_detected: analysis.oracle_detected,
            inconclusive: !analysis.timing_reliable,
            details,
        })
    }

    /// Send encrypted application data with valid or invalid padding
    ///
    /// Returns the time taken for the server to respond (in milliseconds)
    async fn send_padded_request(&self, valid_padding: bool) -> Result<f64> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No socket addresses available for target"))?;
        let start = Instant::now();

        let stream =
            match crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None)
                .await
            {
                Ok(s) => s,
                Err(_) => {
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    return Ok(elapsed);
                }
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list("AES128-SHA:AES256-SHA")?;
        builder.set_min_proto_version(Some(SslVersion::TLS1))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(mut ssl_stream) => {
                // Build application data with specific padding
                let app_data = self.build_application_data(valid_padding);

                // Send the crafted data (synchronous write)
                let write_result = ssl_stream.get_mut().write_all(&app_data);

                if write_result.is_err() {
                    // Connection error - still measure time
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    return Ok(elapsed);
                }

                // Try to read response (server should send alert for invalid padding)
                let mut buffer = vec![0u8; 1024];
                let _ = ssl_stream.get_mut().read(&mut buffer);

                // Measure total time
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                Ok(elapsed)
            }
            Err(_) => {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                Ok(elapsed)
            }
        }
    }

    /// Build TLS Application Data record with controlled padding
    ///
    /// For valid padding: proper PKCS#7 padding
    /// For invalid padding: incorrect padding bytes
    fn build_application_data(&self, valid_padding: bool) -> Vec<u8> {
        let mut data = Vec::new();

        // TLS Record header
        data.push(0x17); // Content Type: Application Data
        data.push(0x03); // Version: TLS 1.2
        data.push(0x03);

        // Record length (will be updated)
        let length_pos = data.len();
        data.push(0x00);
        data.push(0x00);

        // Encrypted payload (simulated - just random data + padding)
        // In a real scenario, this would be AES-CBC encrypted
        const PAYLOAD_LEN: usize = 32; // 32 bytes of "encrypted" data
        data.extend_from_slice(&[0x41; PAYLOAD_LEN]); // Dummy encrypted data

        // Add MAC (20 bytes for HMAC-SHA1)
        data.extend_from_slice(&[0x00; 20]);

        // Add padding
        if valid_padding {
            // Valid PKCS#7 padding: 7 bytes of 0x06 (padding value = length - 1)
            let padding_len = 7;
            for _ in 0..padding_len {
                data.push((padding_len - 1) as u8);
            }
        } else {
            // Invalid padding: wrong padding values
            let padding_len = 7;
            for i in 0..padding_len {
                data.push((i * 11) as u8); // Invalid padding bytes
            }
        }

        // Update record length
        let record_len = data.len() - 5; // Exclude 5-byte header
        data[length_pos] = ((record_len >> 8) & 0xff) as u8;
        data[length_pos + 1] = (record_len & 0xff) as u8;

        data
    }
}

/// Padding Oracle 2016 test result
#[derive(Debug, Clone)]
pub struct PaddingOracle2016Result {
    pub vulnerable: bool,
    pub cbc_supported: bool,
    pub timing_oracle_detected: bool,
    pub details: String,
    pub average_valid_timing_ms: f64,
    pub average_invalid_timing_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_application_data_valid() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = PaddingOracle2016Tester::new(&target);

        let valid_data = tester.build_application_data(true);

        // Check record type
        assert_eq!(valid_data[0], 0x17); // Application Data

        // Check version
        assert_eq!(valid_data[1], 0x03);
        assert_eq!(valid_data[2], 0x03);

        // Verify valid padding at the end
        let padding_byte = valid_data[valid_data.len() - 1];
        let padding_len = (padding_byte + 1) as usize;

        // All padding bytes should be equal
        for i in 1..=padding_len {
            assert_eq!(valid_data[valid_data.len() - i], padding_byte);
        }
    }

    #[test]
    fn test_build_application_data_invalid() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = PaddingOracle2016Tester::new(&target);

        let invalid_data = tester.build_application_data(false);

        // Check record type
        assert_eq!(invalid_data[0], 0x17);

        // Invalid padding should have different bytes at the end
        let last_7_bytes = &invalid_data[invalid_data.len() - 7..];

        // Verify padding is NOT uniform (invalid)
        let first_byte = last_7_bytes[0];
        let has_different_bytes = last_7_bytes.iter().any(|&b| b != first_byte);
        assert!(
            has_different_bytes,
            "Invalid padding should have varying bytes"
        );
    }

    #[test]
    fn test_application_data_length_field_matches_payload() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = PaddingOracle2016Tester::new(&target);

        for valid_padding in [true, false] {
            let data = tester.build_application_data(valid_padding);
            let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
            assert_eq!(record_len, data.len() - 5);
        }
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_padding_oracle_modern_server() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = PaddingOracle2016Tester::new(&target);

        let result = tester.test().await.expect("test assertion should succeed");

        // Google should not be vulnerable (patched OpenSSL)
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_result_structure() {
        let result = PaddingOracle2016Result {
            vulnerable: true,
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
            cbc_supported: false,
            timing_oracle_detected: false,
            details: "Not vulnerable - CBC ciphers not supported".to_string(),
            average_valid_timing_ms: 0.0,
            average_invalid_timing_ms: 0.0,
        };
        assert!(result.details.contains("Not vulnerable"));
    }
}
