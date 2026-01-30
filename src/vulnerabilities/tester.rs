// Vulnerability Tester - Main orchestrator for all vulnerability checks

use super::{Severity, VulnerabilityResult, VulnerabilityType};
use crate::Result;
use crate::ciphers::tester::CipherTester;
use crate::protocols::{Protocol, tester::ProtocolTester};
use crate::utils::network::Target;
use std::collections::HashMap;

/// Collects a vulnerability result, logging any errors
fn collect_result(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<VulnerabilityResult>,
    test_name: &str,
) {
    match result {
        Ok(r) => results.push(r),
        Err(e) => tracing::warn!("{} test failed: {}", test_name, e),
    }
}

/// Collects multiple vulnerability results, logging any errors
fn collect_results(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<Vec<VulnerabilityResult>>,
    test_name: &str,
) {
    match result {
        Ok(r) => results.extend(r),
        Err(e) => tracing::warn!("{} test failed: {}", test_name, e),
    }
}

/// Collects an optional vulnerability result, logging any errors
fn collect_optional_result(
    results: &mut Vec<VulnerabilityResult>,
    result: Result<Option<VulnerabilityResult>>,
    test_name: &str,
) {
    match result {
        Ok(Some(r)) => results.push(r),
        Ok(None) => {}
        Err(e) => tracing::warn!("{} test failed: {}", test_name, e),
    }
}

/// Main vulnerability scanner
pub struct VulnerabilityScanner {
    target: Target,
    protocol_tester: ProtocolTester,
    cipher_tester: CipherTester,
    skip_fallback: bool,
    skip_compression: bool,
    skip_heartbleed: bool,
    skip_renegotiation: bool,
}

impl VulnerabilityScanner {
    /// Create new vulnerability scanner
    pub fn new(target: Target) -> Self {
        let protocol_tester = ProtocolTester::new(target.clone());
        let cipher_tester = CipherTester::new(target.clone());

        Self {
            target,
            protocol_tester,
            cipher_tester,
            skip_fallback: false,
            skip_compression: false,
            skip_heartbleed: false,
            skip_renegotiation: false,
        }
    }

    /// Create new vulnerability scanner with CLI args
    pub fn with_args(target: Target, args: &crate::Args) -> Self {
        let mut protocol_tester = ProtocolTester::new(target.clone());
        let mut cipher_tester = CipherTester::new(target.clone());

        // Enable testing all IPs if specified
        if args.network.test_all_ips {
            protocol_tester = protocol_tester.with_test_all_ips(true);
            cipher_tester = cipher_tester.with_test_all_ips(true);
        }

        Self {
            target,
            protocol_tester,
            cipher_tester,
            skip_fallback: args.scan.no_fallback,
            skip_compression: args.scan.no_compression,
            skip_heartbleed: args.scan.no_heartbleed,
            skip_renegotiation: args.scan.no_renegotiation,
        }
    }

    /// Test all vulnerabilities (PARALLELIZED for maximum performance)
    ///
    /// Orchestrates the complete vulnerability scan in three phases:
    /// 1. Protocol detection - identify supported TLS/SSL versions
    /// 2. Cipher caching - test ciphers for supported protocols
    /// 3. Vulnerability tests - run all checks in parallel
    pub async fn test_all(&self) -> Result<Vec<VulnerabilityResult>> {
        // Step 1: Detect supported protocols
        let protocols = self.detect_protocols().await?;

        // Step 2: Cache ciphers for supported protocols
        let cipher_cache = self.cache_ciphers(&protocols).await?;

        // Step 3: Run vulnerability tests in parallel
        let results = self.run_vulnerability_tests(&cipher_cache).await;

        Ok(results)
    }

    /// Detects which protocols are supported by the target
    async fn detect_protocols(&self) -> Result<Vec<Protocol>> {
        let protocol_results = self.protocol_tester.test_all_protocols().await?;

        let supported = protocol_results
            .iter()
            .filter(|r| r.supported)
            .map(|r| r.protocol)
            .collect();

        Ok(supported)
    }

    /// Caches cipher test results for all supported protocols
    async fn cache_ciphers(
        &self,
        protocols: &[Protocol],
    ) -> Result<HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>> {
        let mut cipher_cache = HashMap::new();

        for protocol in protocols {
            // Skip QUIC - not supported by cipher tester
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let cipher_summary = self.cipher_tester.test_protocol_ciphers(*protocol).await?;
            cipher_cache.insert(*protocol, cipher_summary);
        }

        Ok(cipher_cache)
    }

    /// Runs all vulnerability tests in parallel
    ///
    /// Executes all vulnerability checks concurrently using tokio::join! for
    /// maximum performance. Results are collected with partial success handling
    /// (if one test fails, others still succeed).
    async fn run_vulnerability_tests(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Vec<VulnerabilityResult> {
        let mut results = Vec::new();

        // Create futures for all tests
        let drown_future = self.test_drown();
        let poodle_ssl_future = self.test_poodle_ssl();
        let poodle_variants_future = self.test_poodle_variants();
        let rc4_future = self.test_rc4_cached(cipher_cache);
        let des3_future = self.test_3des_cached(cipher_cache);
        let null_future = self.test_null_ciphers_cached(cipher_cache);
        let export_future = self.test_export_ciphers_cached(cipher_cache);
        let beast_future = self.test_beast_cached(cipher_cache);
        let early_data_future = self.test_early_data();
        let padding_oracle_future = self.test_padding_oracle_2016();

        // Conditional futures (respect CLI flags)
        let renegotiation_future = self.test_renegotiation_if_enabled();
        let fallback_future = self.test_fallback_if_enabled();
        let compression_future = self.test_compression_if_enabled();
        let heartbleed_future = self.test_heartbleed_if_enabled();

        // Execute ALL tests in PARALLEL
        let (
            drown_result,
            poodle_ssl_result,
            poodle_variants_result,
            rc4_result,
            des3_result,
            null_result,
            export_result,
            beast_result,
            renegotiation_result,
            fallback_result,
            compression_result,
            heartbleed_result,
            early_data_result,
            padding_oracle_result,
        ) = tokio::join!(
            drown_future,
            poodle_ssl_future,
            poodle_variants_future,
            rc4_future,
            des3_future,
            null_future,
            export_future,
            beast_future,
            renegotiation_future,
            fallback_future,
            compression_future,
            heartbleed_future,
            early_data_future,
            padding_oracle_future,
        );

        // Collect results - allow partial success
        collect_result(&mut results, drown_result, "DROWN");
        collect_result(&mut results, poodle_ssl_result, "POODLE SSL");
        collect_results(&mut results, poodle_variants_result, "POODLE variants");
        collect_result(&mut results, rc4_result, "RC4");
        collect_result(&mut results, des3_result, "3DES");
        collect_result(&mut results, null_result, "NULL ciphers");
        collect_result(&mut results, export_result, "EXPORT ciphers");
        collect_result(&mut results, beast_result, "BEAST");
        collect_optional_result(&mut results, renegotiation_result, "Renegotiation");
        collect_optional_result(&mut results, fallback_result, "TLS Fallback");
        collect_optional_result(&mut results, compression_result, "Compression");
        collect_optional_result(&mut results, heartbleed_result, "Heartbleed");
        collect_result(&mut results, early_data_result, "Early data");
        collect_result(&mut results, padding_oracle_result, "Padding oracle");

        results
    }

    /// Tests renegotiation if not skipped via CLI flags
    async fn test_renegotiation_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
        if self.skip_renegotiation {
            return Ok(None);
        }
        self.test_renegotiation().await.map(Some)
    }

    /// Tests TLS fallback if not skipped via CLI flags
    async fn test_fallback_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
        if self.skip_fallback {
            return Ok(None);
        }
        self.test_tls_fallback().await.map(Some)
    }

    /// Tests compression if not skipped via CLI flags
    async fn test_compression_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
        if self.skip_compression {
            return Ok(None);
        }
        self.test_compression().await.map(Some)
    }

    /// Tests heartbleed if not skipped via CLI flags
    async fn test_heartbleed_if_enabled(&self) -> Result<Option<VulnerabilityResult>> {
        if self.skip_heartbleed {
            return Ok(None);
        }
        self.test_heartbleed().await.map(Some)
    }

    /// Test for DROWN (CVE-2016-0800)
    /// Simple: just check if SSLv2 is supported
    pub async fn test_drown(&self) -> Result<VulnerabilityResult> {
        let protocol_result = self.protocol_tester.test_protocol(Protocol::SSLv2).await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::DROWN,
            vulnerable: protocol_result.supported,
            details: if protocol_result.supported {
                "Server supports SSLv2, vulnerable to DROWN attack".to_string()
            } else {
                "Server does not support SSLv2".to_string()
            },
            cve: Some("CVE-2016-0800".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if protocol_result.supported {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    /// Test for RC4 cipher usage (CVE-2013-2566, CVE-2015-2808)
    pub async fn test_rc4(&self) -> Result<VulnerabilityResult> {
        // Check if any protocol supports RC4 ciphers
        let mut has_rc4 = false;
        let mut rc4_details = Vec::new();

        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let cipher_summary = self.cipher_tester.test_protocol_ciphers(protocol).await?;

            let rc4_ciphers: Vec<_> = cipher_summary
                .supported_ciphers
                .iter()
                .filter(|c| c.encryption.contains("RC4"))
                .collect();

            if !rc4_ciphers.is_empty() {
                has_rc4 = true;
                rc4_details.push(format!("{}: {} RC4 cipher(s)", protocol, rc4_ciphers.len()));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: has_rc4,
            details: if has_rc4 {
                format!("Server supports RC4 ciphers: {}", rc4_details.join(", "))
            } else {
                "Server does not support RC4 ciphers".to_string()
            },
            cve: Some("CVE-2013-2566, CVE-2015-2808".to_string()),
            cwe: Some("CWE-326".to_string()),
            severity: if has_rc4 {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    /// Test for 3DES/SWEET32 (CVE-2016-2183)
    pub async fn test_3des(&self) -> Result<VulnerabilityResult> {
        let mut has_3des = false;
        let mut des_details = Vec::new();

        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let cipher_summary = self.cipher_tester.test_protocol_ciphers(protocol).await?;

            let des_ciphers: Vec<_> = cipher_summary
                .supported_ciphers
                .iter()
                .filter(|c| c.encryption.contains("3DES") || c.encryption.contains("DES"))
                .collect();

            if !des_ciphers.is_empty() {
                has_3des = true;
                des_details.push(format!(
                    "{}: {} 3DES/DES cipher(s)",
                    protocol,
                    des_ciphers.len()
                ));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::SWEET32,
            vulnerable: has_3des,
            details: if has_3des {
                format!(
                    "Server supports 3DES/DES ciphers (SWEET32): {}",
                    des_details.join(", ")
                )
            } else {
                "Server does not support 3DES/DES ciphers".to_string()
            },
            cve: Some("CVE-2016-2183".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if has_3des {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    /// Test for NULL ciphers
    pub async fn test_null_ciphers(&self) -> Result<VulnerabilityResult> {
        let mut has_null = false;
        let mut null_details = Vec::new();

        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let cipher_summary = self.cipher_tester.test_protocol_ciphers(protocol).await?;

            if cipher_summary.counts.null_ciphers > 0 {
                has_null = true;
                null_details.push(format!(
                    "{}: {} NULL cipher(s)",
                    protocol, cipher_summary.counts.null_ciphers
                ));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4, // Reusing enum, should add NULL type
            vulnerable: has_null,
            details: if has_null {
                format!(
                    "Server supports NULL encryption ciphers: {}",
                    null_details.join(", ")
                )
            } else {
                "Server does not support NULL ciphers".to_string()
            },
            cve: None,
            cwe: Some("CWE-327".to_string()),
            severity: if has_null {
                Severity::Critical
            } else {
                Severity::Info
            },
        })
    }

    /// Test for EXPORT ciphers (FREAK CVE-2015-0204, LOGJAM CVE-2015-4000)
    pub async fn test_export_ciphers(&self) -> Result<VulnerabilityResult> {
        let mut has_export = false;
        let mut export_details = Vec::new();

        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let cipher_summary = self.cipher_tester.test_protocol_ciphers(protocol).await?;

            if cipher_summary.counts.export_ciphers > 0 {
                has_export = true;
                export_details.push(format!(
                    "{}: {} EXPORT cipher(s)",
                    protocol, cipher_summary.counts.export_ciphers
                ));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::FREAK,
            vulnerable: has_export,
            details: if has_export {
                format!(
                    "Server supports EXPORT ciphers (FREAK/LOGJAM): {}",
                    export_details.join(", ")
                )
            } else {
                "Server does not support EXPORT ciphers".to_string()
            },
            cve: Some("CVE-2015-0204, CVE-2015-4000".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if has_export {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    /// Test for POODLE SSL (CVE-2014-3566)
    /// Simple: check if SSLv3 is supported
    pub async fn test_poodle_ssl(&self) -> Result<VulnerabilityResult> {
        let protocol_result = self.protocol_tester.test_protocol(Protocol::SSLv3).await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::POODLE,
            vulnerable: protocol_result.supported,
            details: if protocol_result.supported {
                "Server supports SSLv3, vulnerable to POODLE attack".to_string()
            } else {
                "Server does not support SSLv3".to_string()
            },
            cve: Some("CVE-2014-3566".to_string()),
            cwe: Some("CWE-310".to_string()),
            severity: if protocol_result.supported {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    /// Test for all POODLE variants (Zombie, GOLDENDOODLE, Sleeping, 0-Length)
    /// Returns a vector of vulnerability results, one for each variant
    pub async fn test_poodle_variants(&self) -> Result<Vec<VulnerabilityResult>> {
        use crate::vulnerabilities::poodle::PoodleTester;

        let tester = PoodleTester::new(&self.target);
        let test_result = tester.test_all_variants().await?;

        let mut results = Vec::new();

        // Convert each variant result to VulnerabilityResult
        for variant_result in test_result.variants {
            // Skip SSLv3 and TLS POODLE as they're already tested separately
            if matches!(
                variant_result.variant,
                crate::vulnerabilities::poodle::PoodleVariant::SslV3
                    | crate::vulnerabilities::poodle::PoodleVariant::Tls
            ) {
                continue;
            }

            let vuln_type = match variant_result.variant {
                crate::vulnerabilities::poodle::PoodleVariant::ZombiePoodle => {
                    VulnerabilityType::ZombiePoodle
                }
                crate::vulnerabilities::poodle::PoodleVariant::GoldenDoodle => {
                    VulnerabilityType::GoldenDoodle
                }
                crate::vulnerabilities::poodle::PoodleVariant::SleepingPoodle => {
                    VulnerabilityType::SleepingPoodle
                }
                crate::vulnerabilities::poodle::PoodleVariant::OpenSsl0Length => {
                    VulnerabilityType::OpenSsl0Length
                }
                _ => continue, // Skip SSLv3 and TLS variants
            };

            let severity = if variant_result.vulnerable {
                match variant_result.variant {
                    crate::vulnerabilities::poodle::PoodleVariant::ZombiePoodle
                    | crate::vulnerabilities::poodle::PoodleVariant::GoldenDoodle => Severity::High,
                    crate::vulnerabilities::poodle::PoodleVariant::SleepingPoodle => {
                        Severity::Medium
                    }
                    crate::vulnerabilities::poodle::PoodleVariant::OpenSsl0Length => Severity::High,
                    _ => Severity::Info,
                }
            } else {
                Severity::Info
            };

            results.push(VulnerabilityResult {
                vuln_type,
                vulnerable: variant_result.vulnerable,
                details: variant_result.details,
                cve: Some(variant_result.variant.cve().to_string()),
                cwe: Some("CWE-310".to_string()), // Cryptographic Issues
                severity,
            });
        }

        Ok(results)
    }

    /// Test for BEAST (CVE-2011-3389)
    /// Affects TLS 1.0 with CBC ciphers
    pub async fn test_beast(&self) -> Result<VulnerabilityResult> {
        let protocol_result = self.protocol_tester.test_protocol(Protocol::TLS10).await?;

        if !protocol_result.supported {
            return Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::BEAST,
                vulnerable: false,
                details: "Server does not support TLS 1.0".to_string(),
                cve: Some("CVE-2011-3389".to_string()),
                cwe: Some("CWE-326".to_string()),
                severity: Severity::Info,
            });
        }

        // Check for CBC ciphers in TLS 1.0
        let cipher_summary = self
            .cipher_tester
            .test_protocol_ciphers(Protocol::TLS10)
            .await?;

        let cbc_ciphers: Vec<_> = cipher_summary
            .supported_ciphers
            .iter()
            .filter(|c| c.encryption.contains("CBC"))
            .collect();

        let vulnerable = !cbc_ciphers.is_empty();

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::BEAST,
            vulnerable,
            details: if vulnerable {
                format!(
                    "Server supports TLS 1.0 with {} CBC cipher(s), potentially vulnerable to BEAST",
                    cbc_ciphers.len()
                )
            } else {
                "Server supports TLS 1.0 but no CBC ciphers".to_string()
            },
            cve: Some("CVE-2011-3389".to_string()),
            cwe: Some("CWE-326".to_string()),
            severity: if vulnerable {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    /// Test for insecure renegotiation (CVE-2009-3555)
    /// Requires checking for renegotiation_info extension
    pub async fn test_renegotiation(&self) -> Result<VulnerabilityResult> {
        use crate::protocols::renegotiation::RenegotiationTester;

        let tester = RenegotiationTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Renegotiation,
            vulnerable: result.vulnerable,
            details: result.details,
            cve: Some("CVE-2009-3555".to_string()),
            cwe: Some("CWE-310".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    /// Test for TLS_FALLBACK_SCSV support (CVE-2014-8730)
    pub async fn test_tls_fallback(&self) -> Result<VulnerabilityResult> {
        use crate::protocols::fallback_scsv::FallbackScsvTester;

        let mut tester = FallbackScsvTester::new(&self.target);
        let result = tester.test().await?;

        // Determine severity based on TLS 1.3 support
        // If TLS 1.3+ is supported, downgrade attacks are mitigated by TLS 1.3's
        // built-in downgrade protection, reducing the severity from HIGH to MEDIUM
        let severity = if result.vulnerable {
            if result.has_tls13_or_higher {
                Severity::Medium // TLS 1.3 has built-in downgrade protection
            } else {
                Severity::High // No TLS 1.3, SCSV is critical
            }
        } else {
            Severity::Info
        };

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::TLSFallback,
            vulnerable: result.vulnerable,
            details: result.details,
            cve: Some("CVE-2014-8730".to_string()),
            cwe: Some("CWE-757".to_string()),
            severity,
        })
    }

    /// Test for TLS Compression (CRIME - CVE-2012-4929)
    pub async fn test_compression(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::crime::CrimeTester;

        let tester = CrimeTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::CRIME,
            vulnerable: result.vulnerable,
            details: result.details,
            cve: Some("CVE-2012-4929".to_string()),
            cwe: Some("CWE-310".to_string()),
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    /// Test for Heartbleed (CVE-2014-0160)
    pub async fn test_heartbleed(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::heartbleed::HeartbleedTester;

        let tester = HeartbleedTester::new(&self.target);
        let vulnerable = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable,
            details: if vulnerable {
                "Server is vulnerable to Heartbleed (CVE-2014-0160) - can leak memory contents including sensitive data".to_string()
            } else {
                "Server is not vulnerable to Heartbleed".to_string()
            },
            cve: Some("CVE-2014-0160".to_string()),
            cwe: Some("CWE-119".to_string()),
            severity: if vulnerable {
                Severity::Critical
            } else {
                Severity::Info
            },
        })
    }

    /// Test for 0-RTT / Early Data replay attacks (TLS 1.3)
    pub async fn test_early_data(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::early_data::EarlyDataTester;

        let tester = EarlyDataTester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::EarlyDataReplay,
            vulnerable: result.vulnerable,
            details: result.details,
            cve: None,                        // No specific CVE, but references RFC 8446
            cwe: Some("CWE-294".to_string()), // CWE-294: Authentication Bypass by Capture-replay
            severity: if result.vulnerable {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    /// Test for OpenSSL Padding Oracle (CVE-2016-2107)
    /// Affects OpenSSL 1.0.1 - 1.0.1t and 1.0.2 - 1.0.2h with AES-NI
    pub async fn test_padding_oracle_2016(&self) -> Result<VulnerabilityResult> {
        use crate::vulnerabilities::padding_oracle_2016::PaddingOracle2016Tester;

        let tester = PaddingOracle2016Tester::new(&self.target);
        let result = tester.test().await?;

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::PaddingOracle2016,
            vulnerable: result.vulnerable,
            details: result.details,
            cve: Some("CVE-2016-2107".to_string()),
            cwe: Some("CWE-203".to_string()), // CWE-203: Observable Discrepancy (timing attack)
            severity: if result.vulnerable {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    /// Get vulnerability summary
    pub fn summarize_results(results: &[VulnerabilityResult]) -> VulnerabilitySummary {
        let mut summary = VulnerabilitySummary::default();

        for result in results {
            if result.vulnerable {
                summary.total_vulnerable += 1;

                match result.severity {
                    Severity::Critical => summary.critical += 1,
                    Severity::High => summary.high += 1,
                    Severity::Medium => summary.medium += 1,
                    Severity::Low => summary.low += 1,
                    Severity::Info => {}
                }
            }
        }

        summary.total_tested = results.len();
        summary
    }

    // ========================================================================
    // CACHED VERSIONS - Use pre-computed cipher results to avoid re-testing
    // ========================================================================

    /// Test for RC4 cipher usage - cached version
    async fn test_rc4_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        let mut has_rc4 = false;
        let mut rc4_details = Vec::new();

        for (protocol, cipher_summary) in cipher_cache {
            let rc4_ciphers: Vec<_> = cipher_summary
                .supported_ciphers
                .iter()
                .filter(|c| c.encryption.contains("RC4"))
                .collect();

            if !rc4_ciphers.is_empty() {
                has_rc4 = true;
                rc4_details.push(format!("{}: {} RC4 cipher(s)", protocol, rc4_ciphers.len()));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4,
            vulnerable: has_rc4,
            details: if has_rc4 {
                format!("Server supports RC4 ciphers: {}", rc4_details.join(", "))
            } else {
                "Server does not support RC4 ciphers".to_string()
            },
            cve: Some("CVE-2013-2566, CVE-2015-2808".to_string()),
            cwe: Some("CWE-326".to_string()),
            severity: if has_rc4 {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    /// Test for 3DES/SWEET32 - cached version
    async fn test_3des_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        let mut has_3des = false;
        let mut des_details = Vec::new();

        for (protocol, cipher_summary) in cipher_cache {
            let des_ciphers: Vec<_> = cipher_summary
                .supported_ciphers
                .iter()
                .filter(|c| c.encryption.contains("3DES") || c.encryption.contains("DES"))
                .collect();

            if !des_ciphers.is_empty() {
                has_3des = true;
                des_details.push(format!(
                    "{}: {} 3DES/DES cipher(s)",
                    protocol,
                    des_ciphers.len()
                ));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::SWEET32,
            vulnerable: has_3des,
            details: if has_3des {
                format!(
                    "Server supports 3DES/DES ciphers (SWEET32): {}",
                    des_details.join(", ")
                )
            } else {
                "Server does not support 3DES/DES ciphers".to_string()
            },
            cve: Some("CVE-2016-2183".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if has_3des {
                Severity::Medium
            } else {
                Severity::Info
            },
        })
    }

    /// Test for NULL ciphers - cached version
    async fn test_null_ciphers_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        let mut has_null = false;
        let mut null_details = Vec::new();

        for (protocol, cipher_summary) in cipher_cache {
            if cipher_summary.counts.null_ciphers > 0 {
                has_null = true;
                null_details.push(format!(
                    "{}: {} NULL cipher(s)",
                    protocol, cipher_summary.counts.null_ciphers
                ));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::RC4, // Reusing enum, should add NULL type
            vulnerable: has_null,
            details: if has_null {
                format!(
                    "Server supports NULL encryption ciphers: {}",
                    null_details.join(", ")
                )
            } else {
                "Server does not support NULL ciphers".to_string()
            },
            cve: None,
            cwe: Some("CWE-327".to_string()),
            severity: if has_null {
                Severity::Critical
            } else {
                Severity::Info
            },
        })
    }

    /// Test for EXPORT ciphers - cached version
    async fn test_export_ciphers_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        let mut has_export = false;
        let mut export_details = Vec::new();

        for (protocol, cipher_summary) in cipher_cache {
            if cipher_summary.counts.export_ciphers > 0 {
                has_export = true;
                export_details.push(format!(
                    "{}: {} EXPORT cipher(s)",
                    protocol, cipher_summary.counts.export_ciphers
                ));
            }
        }

        Ok(VulnerabilityResult {
            vuln_type: VulnerabilityType::FREAK,
            vulnerable: has_export,
            details: if has_export {
                format!(
                    "Server supports EXPORT ciphers (FREAK/LOGJAM): {}",
                    export_details.join(", ")
                )
            } else {
                "Server does not support EXPORT ciphers".to_string()
            },
            cve: Some("CVE-2015-0204, CVE-2015-4000".to_string()),
            cwe: Some("CWE-327".to_string()),
            severity: if has_export {
                Severity::High
            } else {
                Severity::Info
            },
        })
    }

    /// Test for BEAST - cached version
    async fn test_beast_cached(
        &self,
        cipher_cache: &HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>,
    ) -> Result<VulnerabilityResult> {
        // Check if TLS 1.0 is in cache (meaning it's supported)
        if let Some(cipher_summary) = cipher_cache.get(&Protocol::TLS10) {
            let cbc_ciphers: Vec<_> = cipher_summary
                .supported_ciphers
                .iter()
                .filter(|c| c.encryption.contains("CBC"))
                .collect();

            let vulnerable = !cbc_ciphers.is_empty();

            Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::BEAST,
                vulnerable,
                details: if vulnerable {
                    format!(
                        "Server supports TLS 1.0 with {} CBC cipher(s), potentially vulnerable to BEAST",
                        cbc_ciphers.len()
                    )
                } else {
                    "Server supports TLS 1.0 but no CBC ciphers".to_string()
                },
                cve: Some("CVE-2011-3389".to_string()),
                cwe: Some("CWE-326".to_string()),
                severity: if vulnerable {
                    Severity::Medium
                } else {
                    Severity::Info
                },
            })
        } else {
            // TLS 1.0 not supported
            Ok(VulnerabilityResult {
                vuln_type: VulnerabilityType::BEAST,
                vulnerable: false,
                details: "Server does not support TLS 1.0".to_string(),
                cve: Some("CVE-2011-3389".to_string()),
                cwe: Some("CWE-326".to_string()),
                severity: Severity::Info,
            })
        }
    }
}

/// Vulnerability scan summary
#[derive(Debug, Clone, Default)]
pub struct VulnerabilitySummary {
    pub total_tested: usize,
    pub total_vulnerable: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl std::fmt::Display for VulnerabilitySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Vulnerability Scan Summary:")?;
        writeln!(f, "  Total Tests:  {}", self.total_tested)?;
        writeln!(f, "  Vulnerabilities Found: {}", self.total_vulnerable)?;
        writeln!(f)?;

        if self.total_vulnerable > 0 {
            writeln!(f, "  By Severity:")?;
            if self.critical > 0 {
                writeln!(f, "    Critical: {}", self.critical)?;
            }
            if self.high > 0 {
                writeln!(f, "    High:     {}", self.high)?;
            }
            if self.medium > 0 {
                writeln!(f, "    Medium:   {}", self.medium)?;
            }
            if self.low > 0 {
                writeln!(f, "    Low:      {}", self.low)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_drown_detection() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let scanner = VulnerabilityScanner::new(target);

        let result = scanner
            .test_drown()
            .await
            .expect("test assertion should succeed");

        // Google should not be vulnerable to DROWN
        assert!(!result.vulnerable);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_rc4_detection() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let scanner = VulnerabilityScanner::new(target);

        let result = scanner
            .test_rc4()
            .await
            .expect("test assertion should succeed");

        // Google should not support RC4
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_summary_formatting() {
        let summary = VulnerabilitySummary {
            total_tested: 10,
            total_vulnerable: 3,
            critical: 1,
            high: 1,
            medium: 1,
            low: 0,
        };

        let output = summary.to_string();
        assert!(output.contains("Total Tests:  10"));
        assert!(output.contains("Vulnerabilities Found: 3"));
        assert!(output.contains("Critical: 1"));
    }
}
