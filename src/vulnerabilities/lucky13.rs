// Lucky13 Vulnerability Test
// CVE-2013-0169
//
// Lucky13 is a timing attack against CBC mode ciphers in TLS.
// It exploits timing differences in MAC verification to recover plaintext.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout};

/// Lucky13 vulnerability tester
pub struct Lucky13Tester {
    target: Target,
}

impl Lucky13Tester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Timing test configuration
    const MIN_SAMPLES: usize = 15; // Minimum samples for statistical significance
    const SAMPLES: usize = 25; // Target number of samples
    const WARMUP_SAMPLES: usize = 5; // Warmup samples to discard (cache warmup)
    const COEFFICIENT_OF_VARIATION_MAX: f64 = 0.5; // Max acceptable CV
    const TIMING_THRESHOLD_PERCENT: f64 = 15.0; // Minimum % difference for timing oracle
    const MIN_TIMING_THRESHOLD_MS: f64 = 10.0; // Minimum absolute difference (network jitter)

    /// Test for Lucky13 vulnerability
    pub async fn test(&self) -> Result<Lucky13TestResult> {
        let cbc_supported = self.test_cbc_ciphers().await?;

        let (timing_result, inconclusive) = if cbc_supported {
            self.test_timing_oracle().await?
        } else {
            (false, false)
        };

        let details = if !cbc_supported {
            "Not vulnerable - CBC ciphers not supported".to_string()
        } else if inconclusive {
            "INCONCLUSIVE: CBC ciphers supported but timing analysis was unreliable due to network conditions. \
             Manual testing recommended.".to_string()
        } else if timing_result {
            "Vulnerable to Lucky13 (CVE-2013-0169) - CBC ciphers with timing oracle detected"
                .to_string()
        } else {
            "Partially vulnerable - CBC ciphers supported but no timing oracle detected. \
             Server may still be vulnerable to more advanced timing attacks."
                .to_string()
        };

        let partially_vulnerable = cbc_supported && !timing_result && !inconclusive;

        Ok(Lucky13TestResult {
            vulnerable: cbc_supported && timing_result,
            partially_vulnerable,
            cbc_supported,
            timing_oracle: timing_result,
            inconclusive,
            details,
        })
    }

    /// Test if CBC ciphers are supported
    async fn test_cbc_ciphers(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];

        // Test with various CBC ciphers
        let cbc_ciphers = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA";

        match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None).await {
            Ok(stream) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;
                builder.set_cipher_list(cbc_ciphers)?;

                let connector = builder.build();
                match connector.connect(&self.target.hostname, std_stream) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Test for timing oracle by sending malformed MAC
    /// Returns (timing_oracle_detected, inconclusive)
    /// Uses proper statistical analysis with warmup, sufficient samples, and CV checks
    async fn test_timing_oracle(&self) -> Result<(bool, bool)> {
        // Warmup phase: discard initial samples to allow cache warmup
        for _ in 0..Self::WARMUP_SAMPLES {
            let _ = self.test_mac_timing(true).await;
            let _ = self.test_mac_timing(false).await;
        }

        // Collect timing samples
        let mut short_padding_times = Vec::with_capacity(Self::SAMPLES);
        let mut long_padding_times = Vec::with_capacity(Self::SAMPLES);

        for _ in 0..Self::SAMPLES {
            if let Ok(time) = self.test_mac_timing(true).await {
                short_padding_times.push(time);
            }
            if let Ok(time) = self.test_mac_timing(false).await {
                long_padding_times.push(time);
            }

            // Small delay between samples to avoid rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Check if we have enough samples for statistical significance
        if short_padding_times.len() < Self::MIN_SAMPLES
            || long_padding_times.len() < Self::MIN_SAMPLES
        {
            // Insufficient samples - return inconclusive
            return Ok((false, true));
        }

        // Calculate statistics
        let avg_short: f64 =
            short_padding_times.iter().sum::<u128>() as f64 / short_padding_times.len() as f64;
        let avg_long: f64 =
            long_padding_times.iter().sum::<u128>() as f64 / long_padding_times.len() as f64;

        // Calculate sample standard deviations (Bessel's correction: N-1)
        // Using N-1 avoids underestimating variance with small samples,
        // which would cause false positive timing oracle detections.
        let short_n = short_padding_times.len() as f64;
        let short_variance: f64 = short_padding_times
            .iter()
            .map(|t| (*t as f64 - avg_short).powi(2))
            .sum::<f64>()
            / (short_n - 1.0).max(1.0);
        let short_stddev = short_variance.sqrt();

        let long_n = long_padding_times.len() as f64;
        let long_variance: f64 = long_padding_times
            .iter()
            .map(|t| (*t as f64 - avg_long).powi(2))
            .sum::<f64>()
            / (long_n - 1.0).max(1.0);
        let long_stddev = long_variance.sqrt();

        // Calculate coefficient of variation (CV) to assess timing reliability
        let short_cv = if avg_short > 0.0 {
            short_stddev / avg_short
        } else {
            f64::MAX
        };
        let long_cv = if avg_long > 0.0 {
            long_stddev / avg_long
        } else {
            f64::MAX
        };

        // Check if timing measurements are reliable (low variance)
        let timing_reliable = short_cv < Self::COEFFICIENT_OF_VARIATION_MAX
            && long_cv < Self::COEFFICIENT_OF_VARIATION_MAX;

        // Calculate timing difference
        let timing_diff = (avg_short - avg_long).abs();
        let timing_diff_percent = if avg_long > 0.0 {
            (timing_diff / avg_long) * 100.0
        } else {
            0.0
        };

        // Statistical significance: difference should be > combined std dev
        let combined_stddev = (short_variance + long_variance).sqrt();
        let statistically_significant =
            timing_diff > 2.0 * combined_stddev + Self::MIN_TIMING_THRESHOLD_MS;

        // Timing oracle detected if:
        // 1. Timing measurements are reliable (low CV)
        // 2. Difference is statistically significant
        // 3. Percentage difference exceeds threshold
        let oracle_detected = timing_reliable
            && statistically_significant
            && timing_diff_percent > Self::TIMING_THRESHOLD_PERCENT;

        // If timing is not reliable, report as inconclusive
        if !timing_reliable {
            return Ok((false, true));
        }

        Ok((oracle_detected, false))
    }

    /// Test MAC timing with different padding lengths
    async fn test_mac_timing(&self, short_padding: bool) -> Result<u128> {
        let addr = self.target.socket_addrs()[0];

        match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None).await {
            Ok(mut stream) => {
                // Send ClientHello
                let client_hello = self.build_client_hello();
                stream.write_all(&client_hello).await?;

                // Read ServerHello, Certificate, ServerHelloDone
                let mut buffer = vec![0u8; 8192];
                timeout(Duration::from_secs(3), stream.read(&mut buffer)).await??;

                // Send ClientKeyExchange
                let client_key_exchange = self.build_client_key_exchange();
                stream.write_all(&client_key_exchange).await?;

                // Send ChangeCipherSpec
                let ccs = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
                stream.write_all(&ccs).await?;

                // Send Finished with invalid MAC (different padding)
                let finished = self.build_malformed_finished(short_padding);

                // Start timing ONLY around the malformed Finished + server response
                // This isolates the MAC verification timing from connection setup noise
                let start = Instant::now();
                stream.write_all(&finished).await?;

                // Measure time until server responds with alert
                let mut response = vec![0u8; 1024];
                let _ = timeout(Duration::from_secs(2), stream.read(&mut response)).await;

                let elapsed = start.elapsed().as_micros();
                Ok(elapsed)
            }
            _ => Err(crate::error::TlsError::Other(
                "Connection failed".to_string(),
            )),
        }
    }

    /// Build ClientHello with CBC cipher preference using ClientHelloBuilder
    fn build_client_hello(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
        builder.for_cbc_ciphers();
        builder.build_minimal().unwrap_or_else(|_| Vec::new())
    }

    /// Build ClientKeyExchange
    fn build_client_key_exchange(&self) -> Vec<u8> {
        vec![
            0x16, 0x03, 0x01, 0x00, 0x86, // Record header
            0x10, // ClientKeyExchange
            0x00, 0x00, 0x82, // Length
            0x00,
            0x80, // Encrypted PMS length
                  // 128 bytes of encrypted premaster secret (dummy data)
        ]
        .into_iter()
        .chain(vec![0xaa; 128])
        .collect()
    }

    /// Build Finished message with malformed MAC
    fn build_malformed_finished(&self, short_padding: bool) -> Vec<u8> {
        let padding_len = if short_padding { 1 } else { 15 };
        let mut finished = vec![
            0x16, 0x03, 0x01, 0x00, 0x40, // Record header (will update)
            0x14, // Finished
            0x00, 0x00, 0x0c, // Length
        ];

        // Verify data (12 bytes, invalid)
        finished.extend_from_slice(&[0x00; 12]);

        // MAC (20 bytes for SHA1, invalid)
        finished.extend_from_slice(&[0xff; 20]);

        // Padding
        for _ in 0..padding_len {
            finished.push(padding_len as u8 - 1);
        }

        // Update record length
        let rec_len = finished.len() - 5;
        finished[3] = ((rec_len >> 8) & 0xff) as u8;
        finished[4] = (rec_len & 0xff) as u8;

        finished
    }
}

/// Lucky13 test result
#[derive(Debug, Clone)]
pub struct Lucky13TestResult {
    pub vulnerable: bool,
    pub partially_vulnerable: bool,
    pub cbc_supported: bool,
    pub timing_oracle: bool,
    pub inconclusive: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_lucky13_result() {
        let result = Lucky13TestResult {
            vulnerable: false,
            partially_vulnerable: true,
            cbc_supported: true,
            timing_oracle: false,
            inconclusive: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.partially_vulnerable);
        assert!(result.cbc_supported);
    }

    #[test]
    fn test_build_client_key_exchange() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = Lucky13Tester::new(target);
        let msg = tester.build_client_key_exchange();
        assert!(msg.len() > 128);
        assert_eq!(msg[0], 0x16); // Handshake record
        assert_eq!(msg[5], 0x10); // ClientKeyExchange
    }

    #[test]
    fn test_build_malformed_finished_padding() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = Lucky13Tester::new(target);

        let short = tester.build_malformed_finished(true);
        let long = tester.build_malformed_finished(false);

        assert!(short.len() < long.len());
        let short_rec_len = ((short[3] as usize) << 8) | (short[4] as usize);
        let long_rec_len = ((long[3] as usize) << 8) | (long[4] as usize);
        assert_eq!(short_rec_len, short.len() - 5);
        assert_eq!(long_rec_len, long.len() - 5);
    }

    #[test]
    fn test_build_client_hello_minimal() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = Lucky13Tester::new(target);

        let hello = tester.build_client_hello();
        assert!(!hello.is_empty());
        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01); // TLS 1.0 record version
        let record_len = ((hello[3] as usize) << 8) | (hello[4] as usize);
        assert_eq!(record_len, hello.len() - 5);
    }

    #[test]
    fn test_build_malformed_finished_padding_values() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = Lucky13Tester::new(target);

        let short = tester.build_malformed_finished(true);
        let long = tester.build_malformed_finished(false);

        assert_eq!(*short.last().unwrap(), 0x00);
        assert_eq!(*long.last().unwrap(), 0x0e);
    }

    #[test]
    fn test_lucky13_result_details_contains_cbc() {
        let result = Lucky13TestResult {
            vulnerable: false,
            partially_vulnerable: true,
            cbc_supported: true,
            timing_oracle: false,
            inconclusive: false,
            details:
                "Partially vulnerable - CBC ciphers supported but no clear timing oracle detected"
                    .to_string(),
        };

        assert!(result.details.contains("CBC"));
    }

    #[test]
    fn test_lucky13_result_not_vulnerable_details() {
        let result = Lucky13TestResult {
            vulnerable: false,
            partially_vulnerable: false,
            cbc_supported: false,
            timing_oracle: false,
            inconclusive: false,
            details: "Not vulnerable - CBC ciphers not supported".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_lucky13_result_inconclusive() {
        let result = Lucky13TestResult {
            vulnerable: false,
            partially_vulnerable: false,
            cbc_supported: true,
            timing_oracle: false,
            inconclusive: true,
            details: "INCONCLUSIVE: CBC ciphers supported but timing analysis was unreliable"
                .to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.cbc_supported);
    }
}
