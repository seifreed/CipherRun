// POODLE (Padding Oracle On Downgraded Legacy Encryption) Vulnerability Test
// CVE-2014-3566 (SSL 3.0 POODLE)
// CVE-2014-8730 (TLS POODLE)
// CVE-2019-5592 (Zombie POODLE, GOLDENDOODLE, Sleeping POODLE)
// CVE-2011-4576 (OpenSSL 0-Length Fragment)
//
// POODLE exploits flaws in CBC padding validation in SSL 3.0 and some TLS implementations.
// This module implements detection for multiple POODLE variants:
//
// 1. Classic POODLE (SSLv3) - CVE-2014-3566
// 2. TLS POODLE - CVE-2014-8730
// 3. Zombie POODLE - Observable MAC validity oracle despite invalid padding
// 4. GOLDENDOODLE - Padding oracle with specific error responses
// 5. Sleeping POODLE - Timing-based padding oracle
// 6. OpenSSL 0-Length - CVE-2011-4576 - Zero-length fragment vulnerability
//
// Detection methodology based on Tripwire padcheck and SSL Labs approach:
// Send deliberately malformed TLS records with different padding/MAC combinations
// and analyze server responses for observable differences (padding oracles).

mod network_probes;
mod oracle_detection;
mod record_builder;

use crate::Result;
use crate::utils::network::Target;
use crate::utils::timing::{TimingOracleConfig, TimingSampleSet, detect_timing_oracle};
use crate::utils::{VulnSslConfig, test_vuln_ssl_connection};
use std::time::Duration;

/// POODLE vulnerability tester
pub struct PoodleTester<'a> {
    target: &'a Target,
}

impl<'a> PoodleTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self { target }
    }

    /// Test for all POODLE vulnerability variants
    pub async fn test(&self) -> Result<PoodleTestResult> {
        let ssl3_supported = self.test_ssl3().await?;
        let tls_poodle = self.test_tls_poodle().await?;

        let vulnerable = ssl3_supported || tls_poodle == Some(true);

        let details = match (ssl3_supported, tls_poodle) {
            (true, Some(true)) => "Vulnerable: SSL 3.0 supported (CVE-2014-3566) AND TLS POODLE detected (CVE-2014-8730)".to_string(),
            (true, _) => "Vulnerable: SSL 3.0 is supported (CVE-2014-3566)".to_string(),
            (false, Some(true)) => "Vulnerable: TLS implementation vulnerable to POODLE (CVE-2014-8730)".to_string(),
            (false, None) => "SSL 3.0 disabled. TLS POODLE test is inconclusive because active CBC padding manipulation is not implemented".to_string(),
            (false, Some(false)) => "Not vulnerable: SSL 3.0 disabled and CBC-based TLS POODLE was not observed".to_string(),
        };

        Ok(PoodleTestResult {
            vulnerable,
            ssl3_supported,
            tls_poodle,
            details,
            variants: Vec::new(),
        })
    }

    /// Test for all POODLE variants including newer CBC padding oracles
    pub async fn test_all_variants(&self) -> Result<PoodleTestResult> {
        let ssl3_supported = self.test_ssl3().await?;

        // Check CBC connectivity once (same check test_tls_poodle does internally).
        let config = VulnSslConfig::tls10_with_ciphers("AES128-SHA:AES256-SHA:DES-CBC3-SHA");
        let cbc_connected = test_vuln_ssl_connection(self.target, config)
            .await
            .map_err(crate::TlsError::from)?;

        // Run each sub-test once and reuse results for both tls_poodle and variants list.
        let zombie = self.test_zombie_poodle().await?;
        let golden = self.test_goldendoodle().await?;
        let sleeping = self.test_sleeping_poodle().await?;
        let openssl_0len = self.test_openssl_0length().await?;

        let tls_poodle = if cbc_connected {
            Some(zombie.vulnerable || golden.vulnerable || sleeping.vulnerable)
        } else {
            None
        };

        let variants = vec![
            Self::ssl3_variant_result(ssl3_supported),
            Self::tls_variant_result(tls_poodle),
            zombie,
            golden,
            sleeping,
            openssl_0len,
        ];

        let vulnerable = variants.iter().any(|v| v.vulnerable);
        let details = if vulnerable {
            let names: Vec<_> = variants
                .iter()
                .filter(|v| v.vulnerable)
                .map(|v| v.variant.name())
                .collect();
            format!("Vulnerable to: {}", names.join(", "))
        } else {
            "Not vulnerable to any POODLE variants".to_string()
        };

        Ok(PoodleTestResult {
            vulnerable,
            ssl3_supported,
            tls_poodle,
            details,
            variants,
        })
    }

    fn ssl3_variant_result(supported: bool) -> PoodleVariantResult {
        PoodleVariantResult {
            variant: PoodleVariant::SslV3,
            vulnerable: supported,
            inconclusive: false,
            details: if supported {
                "SSL 3.0 is supported - vulnerable to classic POODLE attack".to_string()
            } else {
                "SSL 3.0 is not supported".to_string()
            },
            timing_data: None,
        }
    }

    fn tls_variant_result(result: Option<bool>) -> PoodleVariantResult {
        PoodleVariantResult {
            variant: PoodleVariant::Tls,
            vulnerable: result == Some(true),
            inconclusive: result.is_none(),
            details: match result {
                Some(true) => {
                    "TLS implementation vulnerable to POODLE-style attack".to_string()
                }
                None => "TLS POODLE test inconclusive - CBC negotiation succeeded but active padding manipulation is not implemented".to_string(),
                Some(false) => "TLS implementation not vulnerable to POODLE because CBC-based TLS negotiation was not observed".to_string(),
            },
            timing_data: None,
        }
    }

    /// Test if SSL 3.0 is supported
    async fn test_ssl3(&self) -> Result<bool> {
        test_vuln_ssl_connection(self.target, VulnSslConfig::ssl3_only())
            .await
            .map_err(crate::TlsError::from)
    }

    /// Test for TLS POODLE vulnerability
    async fn test_tls_poodle(&self) -> Result<Option<bool>> {
        let config = VulnSslConfig::tls10_with_ciphers("AES128-SHA:AES256-SHA:DES-CBC3-SHA");
        let connected = test_vuln_ssl_connection(self.target, config)
            .await
            .map_err(crate::TlsError::from)?;

        if !connected {
            return Ok(None);
        }

        let zombie = self.test_zombie_poodle().await?;
        let golden = self.test_goldendoodle().await?;
        let sleeping = self.test_sleeping_poodle().await?;

        Ok(Some(
            zombie.vulnerable || golden.vulnerable || sleeping.vulnerable,
        ))
    }

    /// Test for Zombie POODLE - Observable MAC validity oracle
    async fn test_zombie_poodle(&self) -> Result<PoodleVariantResult> {
        self.test_response_oracle_variant(
            PoodleVariant::ZombiePoodle,
            MalformedRecordType::InvalidPaddingValidMac,
            MalformedRecordType::InvalidPaddingInvalidMac,
            "Vulnerable to Zombie POODLE - Observable MAC validity oracle detected",
            "Not vulnerable to Zombie POODLE - No observable MAC oracle",
        )
        .await
    }

    /// Test for GOLDENDOODLE - Padding oracle with error response differentiation
    async fn test_goldendoodle(&self) -> Result<PoodleVariantResult> {
        self.test_response_oracle_variant(
            PoodleVariant::GoldenDoodle,
            MalformedRecordType::ValidPaddingInvalidMac,
            MalformedRecordType::InvalidPaddingInvalidMac,
            "Vulnerable to GOLDENDOODLE - Padding oracle detected via error differentiation",
            "Not vulnerable to GOLDENDOODLE - No padding oracle detected",
        )
        .await
    }

    /// Shared implementation for response-oracle-based POODLE variant tests.
    async fn test_response_oracle_variant(
        &self,
        variant: PoodleVariant,
        record_type_a: MalformedRecordType,
        record_type_b: MalformedRecordType,
        vulnerable_msg: &str,
        not_vulnerable_msg: &str,
    ) -> Result<PoodleVariantResult> {
        if !network_probes::supports_cbc_ciphers(self.target).await? {
            return Ok(Self::cbc_not_supported_result(variant));
        }

        // Increased from 5 to 10 for better statistical significance
        const ITERATIONS: usize = 10;
        let mut responses_a = Vec::new();
        let mut responses_b = Vec::new();

        for _ in 0..ITERATIONS {
            if let Ok(response) =
                network_probes::send_malformed_record(self.target, record_type_a).await
            {
                responses_a.push(response);
            }
            if let Ok(response) =
                network_probes::send_malformed_record(self.target, record_type_b).await
            {
                responses_b.push(response);
            }
        }

        let oracle_detected = oracle_detection::detect_response_oracle(&responses_a, &responses_b);
        // Sample floor mirrors the MIN_TIMING_SAMPLES guard inside detect_response_oracle.
        // Below this, we cannot distinguish "no oracle" from "not enough data".
        const MIN_SAMPLES_FOR_VERDICT: usize = 3;
        let enough_samples = responses_a.len() >= MIN_SAMPLES_FOR_VERDICT
            && responses_b.len() >= MIN_SAMPLES_FOR_VERDICT;

        Ok(PoodleVariantResult {
            variant,
            vulnerable: oracle_detected,
            inconclusive: !oracle_detected && !enough_samples,
            details: if oracle_detected {
                format!(
                    "{} ({} iterations)",
                    vulnerable_msg,
                    responses_a.len().min(responses_b.len())
                )
            } else if !enough_samples {
                format!(
                    "Inconclusive - insufficient probe samples (valid: {}, invalid: {}, need ≥{} each)",
                    responses_a.len(),
                    responses_b.len(),
                    MIN_SAMPLES_FOR_VERDICT,
                )
            } else {
                not_vulnerable_msg.to_string()
            },
            timing_data: None,
        })
    }

    /// Test for Sleeping POODLE - Timing-based padding oracle
    async fn test_sleeping_poodle(&self) -> Result<PoodleVariantResult> {
        if !network_probes::supports_cbc_ciphers(self.target).await? {
            return Ok(Self::cbc_not_supported_result(
                PoodleVariant::SleepingPoodle,
            ));
        }

        // Increased from 20 to 30 for better statistical confidence
        const SAMPLES: usize = 30;
        const TIMING_THRESHOLD_MS: f64 = 15.0;

        let mut valid_timings = TimingSampleSet::with_capacity(SAMPLES);
        let mut invalid_timings = TimingSampleSet::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            if let Ok(timing) = network_probes::measure_response_time(
                self.target,
                MalformedRecordType::ValidPaddingInvalidMac,
            )
            .await
            {
                valid_timings.push(timing);
            }
            if let Ok(timing) = network_probes::measure_response_time(
                self.target,
                MalformedRecordType::InvalidPaddingInvalidMac,
            )
            .await
            {
                invalid_timings.push(timing);
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        if valid_timings.is_empty() || invalid_timings.is_empty() {
            return Ok(PoodleVariantResult {
                variant: PoodleVariant::SleepingPoodle,
                vulnerable: false,
                inconclusive: true,
                details: "Inconclusive - could not collect timing samples".to_string(),
                timing_data: None,
            });
        }

        // Adaptive threshold based on coefficient of variation
        let cv_estimate = valid_timings
            .compute_statistics()
            .map(|s| s.coefficient_of_variation)
            .unwrap_or(0.5);

        let adaptive_threshold = if cv_estimate > 0.3 {
            // High variance network - increase threshold
            TIMING_THRESHOLD_MS * (1.0 + cv_estimate)
        } else {
            TIMING_THRESHOLD_MS
        };

        let config = TimingOracleConfig {
            min_samples: 10, // Increased from 5 for better reliability
            timing_threshold_ms: adaptive_threshold,
            cv_max: 0.5,
            significance_base_ms: 10.0,
        };

        let analysis = match detect_timing_oracle(&valid_timings, &invalid_timings, &config) {
            Some(result) => result,
            None => {
                return Ok(PoodleVariantResult {
                    variant: PoodleVariant::SleepingPoodle,
                    vulnerable: false,
                    // V3 fix: explicit inconclusive flag replaces the previous
                    // string-match approach in `checks.rs` that missed the
                    // "Insufficient timing samples" message.
                    inconclusive: true,
                    details: format!(
                        "Inconclusive - insufficient timing samples (valid: {}, invalid: {}). Need at least 10 samples for reliable detection.",
                        valid_timings.len(),
                        invalid_timings.len()
                    ),
                    timing_data: None,
                });
            }
        };

        let vs = &analysis.valid_stats;
        let is = &analysis.invalid_stats;
        let min_samples = vs.count.min(is.count);

        let timing_data = Some(TimingData {
            valid_padding_avg_ms: vs.mean,
            invalid_padding_avg_ms: is.mean,
            timing_difference_ms: analysis.timing_diff_ms,
            samples_collected: min_samples,
        });

        let details = if analysis.oracle_detected {
            format!(
                "Vulnerable to Sleeping POODLE - Timing oracle detected: valid={:.2}ms (σ={:.2}ms), \
                 invalid={:.2}ms (σ={:.2}ms), diff={:.2}ms (threshold: {:.1}ms). \
                 Statistical significance confirmed.",
                vs.mean, vs.stddev, is.mean, is.stddev, analysis.timing_diff_ms, adaptive_threshold
            )
        } else if !analysis.timing_reliable {
            format!(
                "Inconclusive - Timing measurement unreliable (CV valid={:.2}, invalid={:.2}). \
                 Diff={:.2}ms - high variance suggests network jitter, not timing oracle.",
                vs.coefficient_of_variation, is.coefficient_of_variation, analysis.timing_diff_ms
            )
        } else if analysis.timing_diff_ms <= adaptive_threshold {
            format!(
                "Not vulnerable to Sleeping POODLE - Timing diff ({:.2}ms) below threshold ({:.1}ms). \
                 Valid={:.2}ms, Invalid={:.2}ms",
                analysis.timing_diff_ms, adaptive_threshold, vs.mean, is.mean
            )
        } else {
            format!(
                "Not vulnerable to Sleeping POODLE - Timing difference ({:.2}ms) not statistically significant. \
                 Valid={:.2}ms (σ={:.2}ms), Invalid={:.2}ms (σ={:.2}ms)",
                analysis.timing_diff_ms, vs.mean, vs.stddev, is.mean, is.stddev
            )
        };

        Ok(PoodleVariantResult {
            variant: PoodleVariant::SleepingPoodle,
            vulnerable: analysis.oracle_detected,
            // Timing unreliable (high CV) is Inconclusive, not a clean "not vulnerable"
            inconclusive: !analysis.oracle_detected && !analysis.timing_reliable,
            details,
            timing_data,
        })
    }

    /// Test for OpenSSL 0-Length Fragment vulnerability (CVE-2011-4576)
    async fn test_openssl_0length(&self) -> Result<PoodleVariantResult> {
        if !network_probes::supports_cbc_ciphers(self.target).await? {
            return Ok(Self::cbc_not_supported_result(
                PoodleVariant::OpenSsl0Length,
            ));
        }

        const ITERATIONS: usize = 3;
        let mut vulnerable_count = 0;

        for _ in 0..ITERATIONS {
            if let Ok(response) = network_probes::send_malformed_record(
                self.target,
                MalformedRecordType::ZeroLengthFragment,
            )
            .await
                && (response.connection_accepted || response.shows_differential_behavior)
            {
                vulnerable_count += 1;
            }
        }

        let vulnerable = vulnerable_count >= 2;

        Ok(PoodleVariantResult {
            variant: PoodleVariant::OpenSsl0Length,
            vulnerable,
            inconclusive: false,
            details: if vulnerable {
                format!(
                    "Vulnerable to OpenSSL 0-Length Fragment (CVE-2011-4576) - Server accepts zero-length records ({}/{} iterations)",
                    vulnerable_count, ITERATIONS
                )
            } else {
                "Not vulnerable to OpenSSL 0-Length Fragment - Server properly rejects zero-length records".to_string()
            },
            timing_data: None,
        })
    }

    fn cbc_not_supported_result(variant: PoodleVariant) -> PoodleVariantResult {
        PoodleVariantResult {
            variant,
            vulnerable: false,
            inconclusive: false,
            details: "CBC ciphers not supported - not vulnerable".to_string(),
            timing_data: None,
        }
    }
}

// ── Internal types ──────────────────────────────────────────────────────────

/// Types of malformed TLS records for oracle detection
#[derive(Debug, Clone, Copy)]
pub(crate) enum MalformedRecordType {
    InvalidPaddingValidMac,
    ValidPaddingInvalidMac,
    InvalidPaddingInvalidMac,
    ZeroLengthFragment,
}

/// Server response to malformed record
#[derive(Debug, Clone)]
pub(crate) struct ServerResponse {
    pub connection_accepted: bool,
    pub alert_type: Option<u8>,
    pub response_time_ms: f64,
    pub shows_differential_behavior: bool,
}

// ── Public types ────────────────────────────────────────────────────────────

/// POODLE test result
#[derive(Debug, Clone)]
pub struct PoodleTestResult {
    pub vulnerable: bool,
    pub ssl3_supported: bool,
    pub tls_poodle: Option<bool>,
    pub details: String,
    pub variants: Vec<PoodleVariantResult>,
}

/// POODLE vulnerability variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoodleVariant {
    /// Classic POODLE - CVE-2014-3566 - SSLv3 CBC padding oracle
    SslV3,
    /// TLS POODLE - CVE-2014-8730 - TLS CBC padding oracle
    Tls,
    /// Zombie POODLE - CVE-2019-5592 - Observable MAC validity despite invalid padding
    ZombiePoodle,
    /// GOLDENDOODLE - CVE-2019-5592 - Padding oracle with error response differentiation
    GoldenDoodle,
    /// Sleeping POODLE - CVE-2019-5592 - Timing-based padding oracle
    SleepingPoodle,
    /// OpenSSL 0-Length Fragment - CVE-2011-4576 - Zero-length TLS record vulnerability
    OpenSsl0Length,
}

impl PoodleVariant {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::SslV3 => "POODLE (SSLv3)",
            Self::Tls => "POODLE (TLS)",
            Self::ZombiePoodle => "Zombie POODLE",
            Self::GoldenDoodle => "GOLDENDOODLE",
            Self::SleepingPoodle => "Sleeping POODLE",
            Self::OpenSsl0Length => "OpenSSL 0-Length Fragment",
        }
    }

    /// Get CVE identifier
    pub fn cve(&self) -> &'static str {
        match self {
            Self::SslV3 => "CVE-2014-3566",
            Self::Tls => "CVE-2014-8730",
            Self::ZombiePoodle | Self::GoldenDoodle | Self::SleepingPoodle => "CVE-2019-5592",
            Self::OpenSsl0Length => "CVE-2011-4576",
        }
    }

    /// Get vulnerability description
    pub fn description(&self) -> &'static str {
        match self {
            Self::SslV3 => "SSL 3.0 CBC padding oracle - allows plaintext recovery",
            Self::Tls => "TLS CBC padding oracle - similar to SSLv3 POODLE",
            Self::ZombiePoodle => "Observable MAC validity oracle despite invalid padding",
            Self::GoldenDoodle => "Padding oracle through error response differentiation",
            Self::SleepingPoodle => "Timing-based padding oracle vulnerability",
            Self::OpenSsl0Length => "Zero-length TLS fragment padding vulnerability",
        }
    }
}

/// Result for a specific POODLE variant test
#[derive(Debug, Clone)]
pub struct PoodleVariantResult {
    pub variant: PoodleVariant,
    pub vulnerable: bool,
    /// True when the probe could not reach a conclusive verdict (e.g., insufficient
    /// timing samples, CBC unsupported for the variant, or the server reset the
    /// connection before the oracle could be observed). V3 fix: replaces an
    /// earlier string-based check (`details.contains("Inconclusive")`) that
    /// missed the "Insufficient timing samples" message variant.
    pub inconclusive: bool,
    pub details: String,
    pub timing_data: Option<TimingData>,
}

/// Timing analysis data for timing-based variants
#[derive(Debug, Clone)]
pub struct TimingData {
    pub valid_padding_avg_ms: f64,
    pub invalid_padding_avg_ms: f64,
    pub timing_difference_ms: f64,
    pub samples_collected: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CONTENT_TYPE_APPLICATION_DATA, VERSION_TLS_1_2};

    #[test]
    fn test_poodle_result() {
        let result = PoodleTestResult {
            vulnerable: true,
            ssl3_supported: true,
            tls_poodle: Some(false),
            details: "Test".to_string(),
            variants: Vec::new(),
        };
        assert!(result.vulnerable);
        assert!(result.ssl3_supported);
    }

    #[test]
    fn test_poodle_variant_names() {
        assert_eq!(PoodleVariant::SslV3.name(), "POODLE (SSLv3)");
        assert_eq!(PoodleVariant::Tls.name(), "POODLE (TLS)");
        assert_eq!(PoodleVariant::ZombiePoodle.name(), "Zombie POODLE");
        assert_eq!(PoodleVariant::GoldenDoodle.name(), "GOLDENDOODLE");
        assert_eq!(PoodleVariant::SleepingPoodle.name(), "Sleeping POODLE");
        assert_eq!(
            PoodleVariant::OpenSsl0Length.name(),
            "OpenSSL 0-Length Fragment"
        );
    }

    #[test]
    fn test_poodle_variant_cves() {
        assert_eq!(PoodleVariant::SslV3.cve(), "CVE-2014-3566");
        assert_eq!(PoodleVariant::Tls.cve(), "CVE-2014-8730");
        assert_eq!(PoodleVariant::ZombiePoodle.cve(), "CVE-2019-5592");
        assert_eq!(PoodleVariant::GoldenDoodle.cve(), "CVE-2019-5592");
        assert_eq!(PoodleVariant::SleepingPoodle.cve(), "CVE-2019-5592");
        assert_eq!(PoodleVariant::OpenSsl0Length.cve(), "CVE-2011-4576");
    }

    #[test]
    fn test_poodle_variant_descriptions() {
        assert!(PoodleVariant::SslV3.description().contains("SSL 3.0"));
        assert!(PoodleVariant::Tls.description().contains("TLS"));
        assert!(
            PoodleVariant::OpenSsl0Length
                .description()
                .contains("Zero-length")
        );
    }

    #[test]
    fn test_variant_result_structure() {
        let timing_data = TimingData {
            valid_padding_avg_ms: 15.5,
            invalid_padding_avg_ms: 10.2,
            timing_difference_ms: 5.3,
            samples_collected: 10,
        };

        let result = PoodleVariantResult {
            variant: PoodleVariant::SleepingPoodle,
            vulnerable: true,
            inconclusive: false,
            details: "Timing oracle detected".to_string(),
            timing_data: Some(timing_data),
        };

        assert!(result.vulnerable);
        assert_eq!(result.variant, PoodleVariant::SleepingPoodle);
        assert!(result.timing_data.is_some());

        let timing = result.timing_data.expect("test assertion should succeed");
        assert_eq!(timing.samples_collected, 10);
        assert_eq!(timing.timing_difference_ms, 5.3);
    }

    #[test]
    fn test_variant_result_without_timing_data() {
        let result = PoodleVariantResult {
            variant: PoodleVariant::Tls,
            vulnerable: false,
            inconclusive: false,
            details: "No timing data".to_string(),
            timing_data: None,
        };

        assert!(!result.vulnerable);
        assert!(result.timing_data.is_none());
    }

    #[test]
    fn test_malformed_record_building() {
        let target = crate::utils::network::Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let _tester = PoodleTester::new(&target);

        // Test invalid padding valid MAC record
        let record = record_builder::build_record_invalid_padding_valid_mac();
        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(record[1], (VERSION_TLS_1_2 >> 8) as u8);
        assert_eq!(record[2], (VERSION_TLS_1_2 & 0xff) as u8);
        assert!(record.len() > 48);

        // Verify padding is invalid (inconsistent bytes)
        let padding = &record[record.len() - 7..];
        let first = padding[0];
        assert!(
            padding.iter().any(|&b| b != first),
            "Padding should be inconsistent"
        );

        // Test valid padding invalid MAC record
        let record = record_builder::build_record_valid_padding_invalid_mac();
        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);

        // Verify padding is valid (all bytes same)
        let padding = &record[record.len() - 7..];
        assert!(padding.iter().all(|&b| b == 0x06), "Padding should be 0x06");

        // Test zero-length record
        let record = record_builder::build_zero_length_record();
        assert_eq!(record.len(), 5);
        assert_eq!(record[3], 0x00);
        assert_eq!(record[4], 0x00);
    }

    #[test]
    fn test_client_hello_cbc_structure() {
        let hello = record_builder::build_client_hello_cbc();

        // Verify TLS record header
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03); // TLS 1.2 record layer
        assert_eq!(hello[2], 0x01); // TLS 1.0 record layer (standard)

        // Verify handshake type
        assert_eq!(hello[5], 0x01); // ClientHello

        // Verify TLS version in handshake (TLS 1.2)
        assert_eq!(hello[9], 0x03);
        assert_eq!(hello[10], 0x03);

        // Verify cipher suites present
        assert!(hello.len() > 50, "ClientHello should contain cipher suites");
    }

    #[test]
    fn test_build_record_invalid_padding_invalid_mac() {
        let record = record_builder::build_record_invalid_padding_invalid_mac();

        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
        let padding = &record[record.len() - 7..];
        let first = padding[0];
        assert!(padding.iter().any(|&b| b != first));
    }

    #[test]
    fn test_build_malformed_record_dispatch() {
        let a = record_builder::build_malformed_record(MalformedRecordType::InvalidPaddingValidMac);
        let b = record_builder::build_malformed_record(MalformedRecordType::ValidPaddingInvalidMac);
        let c =
            record_builder::build_malformed_record(MalformedRecordType::InvalidPaddingInvalidMac);
        let d = record_builder::build_malformed_record(MalformedRecordType::ZeroLengthFragment);

        assert!(a.len() > d.len());
        assert!(b.len() > d.len());
        assert!(c.len() > d.len());
        assert_eq!(d.len(), 5);
    }

    #[test]
    fn test_detect_response_oracle_alert_difference() {
        let responses_a = vec![
            ServerResponse {
                connection_accepted: true,
                alert_type: Some(20),
                response_time_ms: 5.0,
                shows_differential_behavior: true,
            },
            ServerResponse {
                connection_accepted: true,
                alert_type: Some(20),
                response_time_ms: 6.0,
                shows_differential_behavior: true,
            },
        ];
        let responses_b = vec![ServerResponse {
            connection_accepted: true,
            alert_type: Some(40),
            response_time_ms: 5.5,
            shows_differential_behavior: true,
        }];

        assert!(oracle_detection::detect_response_oracle(
            &responses_a,
            &responses_b
        ));
    }

    #[test]
    fn test_detect_response_oracle_timing_difference() {
        let responses_a = vec![
            ServerResponse {
                connection_accepted: true,
                alert_type: None,
                response_time_ms: 1.0,
                shows_differential_behavior: false,
            },
            ServerResponse {
                connection_accepted: true,
                alert_type: None,
                response_time_ms: 1.5,
                shows_differential_behavior: false,
            },
            ServerResponse {
                connection_accepted: true,
                alert_type: None,
                response_time_ms: 1.2,
                shows_differential_behavior: false,
            },
        ];
        let responses_b = vec![
            ServerResponse {
                connection_accepted: true,
                alert_type: None,
                response_time_ms: 50.0,
                shows_differential_behavior: false,
            },
            ServerResponse {
                connection_accepted: true,
                alert_type: None,
                response_time_ms: 52.0,
                shows_differential_behavior: false,
            },
            ServerResponse {
                connection_accepted: true,
                alert_type: None,
                response_time_ms: 51.0,
                shows_differential_behavior: false,
            },
        ];

        assert!(oracle_detection::detect_response_oracle(
            &responses_a,
            &responses_b
        ));
    }

    #[test]
    fn test_build_malformed_record_selector() {
        let record =
            record_builder::build_malformed_record(MalformedRecordType::ZeroLengthFragment);
        assert_eq!(record.len(), 5);
        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
    }

    #[test]
    fn test_detect_response_oracle_no_difference() {
        let responses_a = vec![
            ServerResponse {
                connection_accepted: false,
                alert_type: Some(40),
                response_time_ms: 5.0,
                shows_differential_behavior: false,
            },
            ServerResponse {
                connection_accepted: false,
                alert_type: Some(40),
                response_time_ms: 6.0,
                shows_differential_behavior: false,
            },
        ];
        let responses_b = vec![
            ServerResponse {
                connection_accepted: false,
                alert_type: Some(40),
                response_time_ms: 5.5,
                shows_differential_behavior: false,
            },
            ServerResponse {
                connection_accepted: false,
                alert_type: Some(40),
                response_time_ms: 5.2,
                shows_differential_behavior: false,
            },
        ];

        assert!(!oracle_detection::detect_response_oracle(
            &responses_a,
            &responses_b
        ));
        assert!(!oracle_detection::detect_response_oracle(&[], &responses_b));
    }

    #[test]
    fn test_record_construction_variants() {
        let valid = record_builder::build_record_valid_padding_invalid_mac();
        assert_eq!(valid[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(valid.len(), 60);
        assert!(valid[valid.len() - 7..].iter().all(|&b| b == 0x06));

        let invalid = record_builder::build_record_invalid_padding_invalid_mac();
        assert_eq!(invalid[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(invalid.len(), 60);
        let unique_padding: std::collections::HashSet<u8> =
            invalid[invalid.len() - 7..].iter().copied().collect();
        assert!(unique_padding.len() > 1);

        let zero = record_builder::build_zero_length_record();
        assert_eq!(zero.len(), 5);
        assert_eq!(zero[0], CONTENT_TYPE_APPLICATION_DATA);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_poodle_ssl3_modern_server() {
        let target = crate::utils::network::Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = PoodleTester::new(&target);

        let result = tester.test().await.expect("test assertion should succeed");

        assert!(!result.ssl3_supported);
        assert!(!result.vulnerable);
    }

    #[tokio::test]
    #[ignore] // Requires network access and vulnerable server
    async fn test_all_variants_modern_server() {
        let target = crate::utils::network::Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = PoodleTester::new(&target);

        let result = tester
            .test_all_variants()
            .await
            .expect("test assertion should succeed");

        assert!(!result.vulnerable);
        assert_eq!(result.variants.len(), 6);

        for variant_result in &result.variants {
            println!(
                "{}: {}",
                variant_result.variant.name(),
                variant_result.details
            );
        }
    }
}
