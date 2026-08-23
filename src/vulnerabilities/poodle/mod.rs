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
mod result;

use crate::Result;
use crate::protocols::{Protocol, ProtocolTester};
use crate::utils::network::Target;
use crate::utils::timing::{TimingOracleConfig, TimingSampleSet, detect_timing_oracle};
use crate::utils::{VulnSslConfig, test_vuln_ssl_connection_outcome};
use std::time::Duration;

pub use result::{PoodleTestResult, PoodleVariant, PoodleVariantResult, TimingData};

/// POODLE vulnerability tester
pub struct PoodleTester<'a> {
    target: &'a Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
    starttls_server_mode: bool,
}

impl<'a> PoodleTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
            starttls_server_mode: false,
        }
    }

    /// Configure STARTTLS negotiation before each POODLE probe.
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

    /// Test for all POODLE vulnerability variants
    pub async fn test(&self) -> Result<PoodleTestResult> {
        let ssl3_supported = self.test_ssl3().await?;
        let tls_poodle = self.test_tls_poodle().await?;

        Ok(PoodleTestResult::from_basic_probes(
            ssl3_supported,
            tls_poodle,
        ))
    }

    /// Test for all POODLE variants including newer CBC padding oracles
    pub async fn test_all_variants(&self) -> Result<PoodleTestResult> {
        let ssl3_supported = self.test_ssl3().await?;

        // Check CBC connectivity once (same check test_tls_poodle does internally).
        let config = VulnSslConfig::tls10_with_ciphers("AES128-SHA:AES256-SHA:DES-CBC3-SHA")
            .with_starttls(self.starttls)
            .with_starttls_hostname(self.starttls_hostname.clone())
            .with_starttls_server_mode(self.starttls_server_mode);
        let cbc_connected = test_vuln_ssl_connection_outcome(self.target, config).await?;

        // Run each sub-test once and reuse results for both tls_poodle and variants list.
        let zombie = self.test_zombie_poodle().await?;
        let golden = self.test_goldendoodle().await?;
        let sleeping = self.test_sleeping_poodle().await?;
        let openssl_0len = self.test_openssl_0length(ssl3_supported).await?;

        let tls_poodle = if cbc_connected == Some(true) {
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

        Ok(PoodleTestResult::from_variant_results(
            ssl3_supported,
            tls_poodle,
            variants,
        ))
    }

    fn ssl3_variant_result(supported: Option<bool>) -> PoodleVariantResult {
        PoodleVariantResult {
            variant: PoodleVariant::SslV3,
            vulnerable: supported == Some(true),
            inconclusive: supported.is_none(),
            details: if supported == Some(true) {
                "SSL 3.0 is supported - vulnerable to classic POODLE attack".to_string()
            } else if supported.is_none() {
                "SSL 3.0 support inconclusive".to_string()
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
                None => "TLS POODLE test inconclusive - no CBC cipher connection could be established to probe for a padding oracle".to_string(),
                Some(false) => "TLS implementation not vulnerable to POODLE because CBC-based TLS negotiation was not observed".to_string(),
            },
            timing_data: None,
        }
    }

    /// Test if SSL 3.0 is supported
    async fn test_ssl3(&self) -> Result<Option<bool>> {
        let protocol = ProtocolTester::new(self.target.clone())
            .with_connect_timeout(Duration::from_secs(5))
            .with_read_timeout(Duration::from_secs(5))
            .with_test_all_ips(true)
            .with_starttls(self.starttls)
            .with_starttls_server_mode(self.starttls_server_mode)
            .test_protocol(Protocol::SSLv3)
            .await?;

        Ok(if protocol.supported {
            Some(true)
        } else if protocol.inconclusive {
            None
        } else {
            Some(false)
        })
    }

    /// Test for TLS POODLE vulnerability
    async fn test_tls_poodle(&self) -> Result<Option<bool>> {
        let config = VulnSslConfig::tls10_with_ciphers("AES128-SHA:AES256-SHA:DES-CBC3-SHA")
            .with_starttls(self.starttls)
            .with_starttls_server_mode(self.starttls_server_mode);
        let connected = test_vuln_ssl_connection_outcome(self.target, config).await?;

        if connected != Some(true) {
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
        match network_probes::supports_cbc_ciphers(
            self.target,
            self.starttls,
            self.starttls_hostname.as_deref(),
            self.starttls_server_mode,
        )
        .await?
        {
            Some(true) => {}
            Some(false) => return Ok(Self::cbc_not_supported_result(variant)),
            None => return Ok(Self::cbc_inconclusive_result(variant)),
        }

        // Increased from 5 to 10 for better statistical significance
        const ITERATIONS: usize = 10;
        let mut responses_a = Vec::new();
        let mut responses_b = Vec::new();

        for _ in 0..ITERATIONS {
            if let Ok(response) = network_probes::send_malformed_record(
                self.target,
                record_type_a,
                self.starttls,
                self.starttls_hostname.as_deref(),
                self.starttls_server_mode,
            )
            .await
            {
                responses_a.push(response);
            }
            if let Ok(response) = network_probes::send_malformed_record(
                self.target,
                record_type_b,
                self.starttls,
                self.starttls_hostname.as_deref(),
                self.starttls_server_mode,
            )
            .await
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
        match network_probes::supports_cbc_ciphers(
            self.target,
            self.starttls,
            self.starttls_hostname.as_deref(),
            self.starttls_server_mode,
        )
        .await?
        {
            Some(true) => {}
            Some(false) => {
                return Ok(Self::cbc_not_supported_result(
                    PoodleVariant::SleepingPoodle,
                ));
            }
            None => return Ok(Self::cbc_inconclusive_result(PoodleVariant::SleepingPoodle)),
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
                self.starttls,
                self.starttls_hostname.as_deref(),
                self.starttls_server_mode,
            )
            .await
            {
                valid_timings.push(timing);
            }
            if let Ok(timing) = network_probes::measure_response_time(
                self.target,
                MalformedRecordType::InvalidPaddingInvalidMac,
                self.starttls,
                self.starttls_hostname.as_deref(),
                self.starttls_server_mode,
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
            valid_padding_median_ms: vs.median,
            invalid_padding_median_ms: is.median,
            valid_padding_p95_ms: vs.p95,
            invalid_padding_p95_ms: is.p95,
            timing_difference_ms: analysis.timing_diff_ms,
            timing_difference_confidence_interval_95_ms: analysis
                .difference_confidence_interval_95_ms,
            samples_collected: min_samples,
        });

        let details = if analysis.oracle_detected {
            format!(
                "Suspected Sleeping POODLE timing oracle (INCONCLUSIVE) - valid mean/median/p95={:.2}/{:.2}/{:.2}ms, \
                 invalid mean/median/p95={:.2}/{:.2}/{:.2}ms, diff={:.2}ms (95% CI {:.2}-{:.2}ms; threshold: {:.1}ms). A remote timing \
                 difference cannot conclusively confirm the oracle (network jitter dwarfs the MAC \
                 timing signal); confirm with a local/low-latency test.",
                vs.mean,
                vs.median,
                vs.p95,
                is.mean,
                is.median,
                is.p95,
                analysis.timing_diff_ms,
                analysis.difference_confidence_interval_95_ms.0,
                analysis.difference_confidence_interval_95_ms.1,
                adaptive_threshold
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
            // A remote timing difference cannot conclusively confirm the oracle
            // (network jitter is orders of magnitude larger than the MAC-timing
            // signal — the same limitation that keeps Lucky13 inconclusive), so a
            // positive detection is reported as suspected/inconclusive, never as a
            // hard vulnerable verdict, to avoid false positives on hardened hosts.
            vulnerable: false,
            inconclusive: analysis.oracle_detected || !analysis.timing_reliable,
            details,
            timing_data,
        })
    }

    /// Test for OpenSSL 0-Length Fragment vulnerability (CVE-2011-4576)
    async fn test_openssl_0length(
        &self,
        ssl3_supported: Option<bool>,
    ) -> Result<PoodleVariantResult> {
        // CVE-2011-4576 is specific to SSL 3.0 CBC record processing in old
        // OpenSSL; a server that does not negotiate SSL 3.0 cannot be affected.
        // Accepting a zero-length application-data record over TLS is normal,
        // RFC-permitted behaviour and is NOT evidence of this vulnerability — the
        // previous heuristic keyed on `connection_accepted`, which is set true
        // whenever the handshake completes, so it flagged every CBC-capable
        // server (Cloudflare, Google, ...) as vulnerable.
        if ssl3_supported == Some(false) {
            return Ok(PoodleVariantResult {
                variant: PoodleVariant::OpenSsl0Length,
                vulnerable: false,
                inconclusive: false,
                details: "Not vulnerable to OpenSSL 0-Length Fragment (CVE-2011-4576) - SSL 3.0 is not supported, so the SSL 3.0-only flaw cannot apply".to_string(),
                timing_data: None,
            });
        }
        if ssl3_supported.is_none() {
            return Ok(PoodleVariantResult {
                variant: PoodleVariant::OpenSsl0Length,
                vulnerable: false,
                inconclusive: true,
                details: "OpenSSL 0-Length Fragment (CVE-2011-4576) inconclusive - SSL 3.0 support could not be determined".to_string(),
                timing_data: None,
            });
        }

        match network_probes::supports_cbc_ciphers(
            self.target,
            self.starttls,
            self.starttls_hostname.as_deref(),
            self.starttls_server_mode,
        )
        .await?
        {
            Some(true) => {}
            Some(false) => {
                return Ok(Self::cbc_not_supported_result(
                    PoodleVariant::OpenSsl0Length,
                ));
            }
            None => return Ok(Self::cbc_inconclusive_result(PoodleVariant::OpenSsl0Length)),
        }

        // SSL 3.0 with CBC is offered. Send the zero-length fragment and treat
        // only an abnormal reaction (the handshake/probe failing to complete) as
        // a signal — normal acceptance is not the flaw. Even so, confirming the
        // memory-disclosure conclusively requires observing leaked plaintext,
        // which is not feasible remotely, so a normally-handled probe is reported
        // inconclusive rather than vulnerable.
        const ITERATIONS: usize = 3;
        let mut probe_anomalies = 0;
        for _ in 0..ITERATIONS {
            match network_probes::send_malformed_record(
                self.target,
                MalformedRecordType::ZeroLengthFragment,
                self.starttls,
                self.starttls_hostname.as_deref(),
                self.starttls_server_mode,
            )
            .await
            {
                Ok(response)
                    if !response.connection_accepted || response.shows_differential_behavior =>
                {
                    probe_anomalies += 1
                }
                _ => {}
            }
        }

        Ok(PoodleVariantResult {
            variant: PoodleVariant::OpenSsl0Length,
            vulnerable: false,
            inconclusive: true,
            details: format!(
                "OpenSSL 0-Length Fragment (CVE-2011-4576) inconclusive - SSL 3.0 with CBC is offered; \
                 confirming the memory-disclosure flaw requires observing leaked plaintext, which a remote \
                 probe cannot do reliably ({}/{} probes saw an abnormal reaction). Disable SSL 3.0.",
                probe_anomalies, ITERATIONS
            ),
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

    fn cbc_inconclusive_result(variant: PoodleVariant) -> PoodleVariantResult {
        PoodleVariantResult {
            variant,
            vulnerable: false,
            inconclusive: true,
            details: "CBC cipher support probe inconclusive - could not complete TLS connection"
                .to_string(),
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
