// Vulnerability tester façade. Public API, constructors, summary and tests stay here.

#[path = "tester/checks.rs"]
mod checks;
#[path = "tester/cipher_checks.rs"]
mod cipher_checks;
#[path = "tester/orchestration.rs"]
mod orchestration;

use super::{Severity, VulnerabilityResult, VulnerabilityType};
use crate::application::ScanRequest;
use crate::ciphers::tester::CipherTester;
use crate::protocols::{Protocol, tester::ProtocolTester};
use crate::utils::network::Target;
use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
struct SelectedVulnerabilityChecks {
    enabled: HashSet<VulnerabilityType>,
}

impl SelectedVulnerabilityChecks {
    fn from_request(args: &ScanRequest) -> Self {
        let mut enabled = HashSet::new();
        if args.scan.vulns.heartbleed {
            enabled.insert(VulnerabilityType::Heartbleed);
        }
        if args.scan.vulns.ccs {
            enabled.insert(VulnerabilityType::CCSInjection);
        }
        if args.scan.vulns.ticketbleed {
            enabled.insert(VulnerabilityType::Ticketbleed);
        }
        if args.scan.vulns.robot {
            enabled.insert(VulnerabilityType::ROBOT);
        }
        if args.scan.vulns.renegotiation {
            enabled.insert(VulnerabilityType::Renegotiation);
        }
        if args.scan.vulns.crime {
            enabled.insert(VulnerabilityType::CRIME);
        }
        if args.scan.vulns.breach {
            enabled.insert(VulnerabilityType::BREACH);
        }
        if args.scan.vulns.poodle {
            enabled.insert(VulnerabilityType::POODLE);
        }
        if args.scan.vulns.fallback {
            enabled.insert(VulnerabilityType::TLSFallback);
        }
        if args.scan.vulns.sweet32 {
            enabled.insert(VulnerabilityType::SWEET32);
        }
        if args.scan.vulns.beast {
            enabled.insert(VulnerabilityType::BEAST);
        }
        if args.scan.vulns.lucky13 {
            enabled.insert(VulnerabilityType::LUCKY13);
        }
        if args.scan.vulns.freak {
            enabled.insert(VulnerabilityType::FREAK);
        }
        if args.scan.vulns.logjam {
            enabled.insert(VulnerabilityType::LOGJAM);
        }
        if args.scan.vulns.drown {
            enabled.insert(VulnerabilityType::DROWN);
        }
        if args.scan.vulns.early_data {
            enabled.insert(VulnerabilityType::EarlyDataReplay);
        }
        Self { enabled }
    }

    fn any(&self) -> bool {
        !self.enabled.is_empty()
    }

    fn count(&self) -> usize {
        self.enabled
            .iter()
            .map(|v| {
                if matches!(v, VulnerabilityType::POODLE) {
                    5
                } else {
                    1
                }
            })
            .sum()
    }

    fn is_enabled(&self, vtype: &VulnerabilityType) -> bool {
        self.enabled.contains(vtype)
    }
}

const FULL_SCAN_TEST_COUNT: usize = 25;
const FAST_SCAN_TEST_COUNT: usize = 15;

/// Main vulnerability scanner
pub struct VulnerabilityScanner {
    target: Target,
    protocol_tester: ProtocolTester,
    cipher_tester: CipherTester,
    sni_hostname: Option<String>,
    broad_scan: bool,
    fast_mode: bool,
    selected_checks: SelectedVulnerabilityChecks,
    skip_fallback: bool,
    skip_compression: bool,
    skip_heartbleed: bool,
    skip_renegotiation: bool,
}

impl VulnerabilityScanner {
    pub fn new(target: Target) -> Self {
        let protocol_tester = ProtocolTester::new(target.clone());
        let cipher_tester = CipherTester::new(target.clone());

        Self {
            target,
            protocol_tester,
            cipher_tester,
            sni_hostname: None,
            broad_scan: true,
            fast_mode: false,
            selected_checks: SelectedVulnerabilityChecks::default(),
            skip_fallback: false,
            skip_compression: false,
            skip_heartbleed: false,
            skip_renegotiation: false,
        }
    }

    pub fn with_args(target: Target, args: &ScanRequest) -> Self {
        let mut protocol_tester = ProtocolTester::new(target.clone());
        let mut cipher_tester = CipherTester::new(target.clone());

        if args.network.test_all_ips {
            protocol_tester = protocol_tester.with_test_all_ips(true);
            cipher_tester = cipher_tester.with_test_all_ips(true);
        }

        let sni_hostname = args.tls.sni_name.clone();
        protocol_tester = protocol_tester.with_sni(sni_hostname.clone());
        cipher_tester = cipher_tester.with_sni(sni_hostname.clone());

        Self {
            target,
            protocol_tester,
            cipher_tester,
            sni_hostname,
            broad_scan: args.scan.vulns.vulnerabilities || args.scan.scope.full,
            fast_mode: args.scan.prefs.fast,
            selected_checks: SelectedVulnerabilityChecks::from_request(args),
            skip_fallback: args.scan.vulns.no_fallback,
            skip_compression: args.scan.vulns.no_compression,
            skip_heartbleed: args.scan.vulns.no_heartbleed,
            skip_renegotiation: args.scan.vulns.no_renegotiation,
        }
    }

    pub fn summarize_results(results: &[VulnerabilityResult]) -> VulnerabilitySummary {
        Self::summarize_results_with_expected(results, results.len())
    }

    pub fn summarize_execution(&self, results: &[VulnerabilityResult]) -> VulnerabilitySummary {
        Self::summarize_results_with_expected(results, self.planned_test_count())
    }

    fn summarize_results_with_expected(
        results: &[VulnerabilityResult],
        total_expected: usize,
    ) -> VulnerabilitySummary {
        let mut summary = VulnerabilitySummary::default();

        for result in results {
            if result.vulnerable {
                summary.total_vulnerable += 1;
                match result.severity {
                    Severity::Critical => summary.critical += 1,
                    Severity::High => summary.high += 1,
                    Severity::Medium => summary.medium += 1,
                    Severity::Low => summary.low += 1,
                    Severity::Info => summary.info += 1,
                }
            }
            if result.inconclusive {
                summary.total_inconclusive += 1;
            }
        }

        summary.total_tested = results.len();
        summary.total_expected = total_expected;
        summary.total_not_executed = total_expected.saturating_sub(results.len());
        summary
    }

    fn planned_test_count(&self) -> usize {
        if !self.broad_scan && self.selected_checks.any() {
            return self.selected_checks.count();
        }

        let mut planned = if self.fast_mode {
            FAST_SCAN_TEST_COUNT
        } else {
            FULL_SCAN_TEST_COUNT
        };
        if self.skip_renegotiation {
            planned = planned.saturating_sub(1);
        }
        if self.skip_fallback {
            planned = planned.saturating_sub(1);
        }
        if self.skip_compression {
            planned = planned.saturating_sub(1);
        }
        if self.skip_heartbleed {
            planned = planned.saturating_sub(1);
        }
        planned
    }
}

/// Vulnerability scan summary
#[derive(Debug, Clone, Default)]
pub struct VulnerabilitySummary {
    pub total_expected: usize,
    pub total_tested: usize,
    pub total_not_executed: usize,
    pub total_vulnerable: usize,
    pub total_inconclusive: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl std::fmt::Display for VulnerabilitySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Vulnerability Scan Summary:")?;
        writeln!(f, "  Planned Checks: {}", self.total_expected)?;
        writeln!(f, "  Executed Checks: {}", self.total_tested)?;
        writeln!(f, "  Not Executed: {}", self.total_not_executed)?;
        writeln!(f, "  Vulnerabilities Found: {}", self.total_vulnerable)?;
        writeln!(f, "  Inconclusive Checks: {}", self.total_inconclusive)?;
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
            if self.info > 0 {
                writeln!(f, "    Info:     {}", self.info)?;
            }
        }

        if self.total_inconclusive > 0 {
            writeln!(
                f,
                "  Review inconclusive checks before treating the scan as a clean pass."
            )?;
        }
        if self.total_not_executed > 0 {
            writeln!(
                f,
                "  Some checks were skipped or failed before producing a result."
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dummy_target() -> Target {
        Target::with_ips(
            "example.test".to_string(),
            443,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed")
    }

    fn make_cipher(encryption: &str) -> crate::ciphers::CipherSuite {
        crate::ciphers::CipherSuite {
            hexcode: "0001".to_string(),
            openssl_name: "OPENSSL_TEST".to_string(),
            iana_name: "IANA_TEST".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "RSA".to_string(),
            authentication: "RSA".to_string(),
            encryption: encryption.to_string(),
            mac: "SHA256".to_string(),
            bits: 128,
            export: false,
        }
    }

    fn make_summary(
        protocol: Protocol,
        ciphers: Vec<crate::ciphers::CipherSuite>,
        counts: crate::ciphers::tester::CipherCounts,
    ) -> crate::ciphers::tester::ProtocolCipherSummary {
        crate::ciphers::tester::ProtocolCipherSummary {
            protocol,
            supported_ciphers: ciphers,
            server_ordered: false,
            server_preference: Vec::new(),
            preferred_cipher: None,
            counts,
            avg_handshake_time_ms: None,
        }
    }

    fn sample_result() -> VulnerabilityResult {
        VulnerabilityResult {
            vuln_type: VulnerabilityType::DROWN,
            vulnerable: true,
            inconclusive: false,
            details: "details".to_string(),
            cve: Some("CVE".to_string()),
            cwe: Some("CWE".to_string()),
            severity: Severity::High,
        }
    }

    #[test]
    fn test_collect_result_ok_and_err() {
        let mut results = Vec::new();
        orchestration::collect_result(
            &mut results,
            Ok(sample_result()),
            VulnerabilityType::Heartbleed,
            "sample",
        );
        orchestration::collect_result(
            &mut results,
            Err(crate::TlsError::Other("boom".to_string())),
            VulnerabilityType::Heartbleed,
            "sample",
        );
        // Should have 2 results: one success and one inconclusive for the error
        assert_eq!(results.len(), 2);
        assert!(!results[0].inconclusive);
        assert!(results[1].inconclusive);
    }

    #[test]
    fn test_collect_results_and_optional() {
        let mut results = Vec::new();
        orchestration::collect_results(
            &mut results,
            Ok(vec![sample_result()]),
            &[VulnerabilityType::Heartbleed],
            "sample",
        );
        orchestration::collect_optional_result(
            &mut results,
            Ok(Some(sample_result())),
            VulnerabilityType::Heartbleed,
            "sample",
        );
        orchestration::collect_optional_result(
            &mut results,
            Ok(None),
            VulnerabilityType::Heartbleed,
            "sample",
        );
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_cached_cipher_vulnerabilities() {
        let scanner = VulnerabilityScanner::new(dummy_target());
        let mut cache = HashMap::new();
        cache.insert(
            Protocol::TLS12,
            make_summary(
                Protocol::TLS12,
                vec![
                    make_cipher("RC4"),
                    make_cipher("3DES"),
                    make_cipher("NULL"),
                    make_cipher("EXPORT"),
                ],
                crate::ciphers::tester::CipherCounts {
                    total: 4,
                    null_ciphers: 1,
                    export_ciphers: 1,
                    low_strength: 1,
                    medium_strength: 1,
                    high_strength: 0,
                    forward_secrecy: 0,
                    aead: 0,
                },
            ),
        );

        assert!(
            scanner
                .test_rc4_cached(&cache)
                .await
                .expect("ok")
                .vulnerable
        );
        assert!(
            scanner
                .test_null_ciphers_cached(&cache)
                .await
                .expect("ok")
                .vulnerable
        );
        assert!(
            scanner
                .test_export_ciphers_cached(&cache)
                .await
                .expect("ok")
                .vulnerable
        );
    }

    #[tokio::test]
    async fn test_beast_cached_with_tls10() {
        let scanner = VulnerabilityScanner::new(dummy_target());
        let mut cache = HashMap::new();
        cache.insert(
            Protocol::TLS10,
            make_summary(
                Protocol::TLS10,
                vec![make_cipher("AES128-CBC")],
                crate::ciphers::tester::CipherCounts {
                    total: 1,
                    null_ciphers: 0,
                    export_ciphers: 0,
                    low_strength: 0,
                    medium_strength: 1,
                    high_strength: 0,
                    forward_secrecy: 0,
                    aead: 0,
                },
            ),
        );

        assert!(
            scanner
                .test_beast_cached(&cache)
                .await
                .expect("ok")
                .vulnerable
        );
    }

    #[test]
    fn test_summarize_results_counts() {
        let results = vec![
            VulnerabilityResult {
                severity: Severity::Critical,
                ..sample_result()
            },
            VulnerabilityResult {
                severity: Severity::High,
                ..sample_result()
            },
            VulnerabilityResult {
                severity: Severity::Medium,
                ..sample_result()
            },
            VulnerabilityResult {
                severity: Severity::Low,
                ..sample_result()
            },
            VulnerabilityResult {
                vulnerable: false,
                severity: Severity::High,
                ..sample_result()
            },
        ];

        let summary = VulnerabilityScanner::summarize_results(&results);
        assert_eq!(summary.total_expected, 5);
        assert_eq!(summary.total_tested, 5);
        assert_eq!(summary.total_not_executed, 0);
        assert_eq!(summary.total_vulnerable, 4);
        assert_eq!(summary.total_inconclusive, 0);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 1);
    }

    #[test]
    fn test_summarize_results_counts_inconclusive() {
        let results = vec![VulnerabilityResult {
            vuln_type: VulnerabilityType::GREASE,
            vulnerable: false,
            inconclusive: true,
            details: "Inconclusive".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Info,
        }];

        let summary = VulnerabilityScanner::summarize_results(&results);
        assert_eq!(summary.total_expected, 1);
        assert_eq!(summary.total_tested, 1);
        assert_eq!(summary.total_not_executed, 0);
        assert_eq!(summary.total_vulnerable, 0);
        assert_eq!(summary.total_inconclusive, 1);
    }

    #[test]
    fn test_summarize_execution_reports_not_executed_checks() {
        let mut scanner = VulnerabilityScanner::new(dummy_target());
        scanner.skip_fallback = true;
        scanner.skip_compression = true;
        scanner.skip_heartbleed = true;
        scanner.skip_renegotiation = true;

        let summary = scanner.summarize_execution(&[]);
        assert_eq!(summary.total_expected, 21);
        assert_eq!(summary.total_tested, 0);
        assert_eq!(summary.total_not_executed, 21);
    }

    #[test]
    fn test_collect_helpers() {
        let mut results = Vec::new();
        orchestration::collect_result(
            &mut results,
            Ok(sample_result()),
            VulnerabilityType::Heartbleed,
            "ok",
        );
        orchestration::collect_results(
            &mut results,
            Ok(vec![sample_result()]),
            &[VulnerabilityType::Heartbleed],
            "ok",
        );
        orchestration::collect_optional_result(
            &mut results,
            Ok(Some(sample_result())),
            VulnerabilityType::Heartbleed,
            "ok",
        );
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_skip_flags_short_circuit() {
        let mut scanner = VulnerabilityScanner::new(dummy_target());
        scanner.skip_fallback = true;
        scanner.skip_compression = true;
        scanner.skip_heartbleed = true;
        scanner.skip_renegotiation = true;

        assert!(
            scanner
                .test_fallback_if_enabled()
                .await
                .expect("ok")
                .is_none()
        );
        assert!(
            scanner
                .test_compression_if_enabled()
                .await
                .expect("ok")
                .is_none()
        );
        assert!(
            scanner
                .test_heartbleed_if_enabled()
                .await
                .expect("ok")
                .is_none()
        );
        assert!(
            scanner
                .test_renegotiation_if_enabled()
                .await
                .expect("ok")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_cache_ciphers_skips_quic_only() {
        let scanner = VulnerabilityScanner::new(dummy_target());
        let cache = scanner
            .cache_ciphers(&[Protocol::QUIC])
            .await
            .expect("test assertion should succeed");
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn test_drown_detection() {
        let scanner = VulnerabilityScanner::new(dummy_target());
        let result = scanner
            .test_drown()
            .await
            .expect("test assertion should succeed");
        assert_eq!(result.vuln_type, VulnerabilityType::DROWN);
    }

    #[tokio::test]
    async fn test_rc4_detection() {
        let scanner = VulnerabilityScanner::new(dummy_target());
        let mut cache = HashMap::new();
        cache.insert(
            Protocol::TLS12,
            make_summary(
                Protocol::TLS12,
                vec![make_cipher("RC4")],
                crate::ciphers::tester::CipherCounts::default(),
            ),
        );
        assert!(
            scanner
                .test_rc4_cached(&cache)
                .await
                .expect("ok")
                .vulnerable
        );
    }

    #[test]
    fn test_summary_formatting() {
        let summary = VulnerabilitySummary {
            total_expected: 10,
            total_tested: 10,
            total_not_executed: 0,
            total_vulnerable: 2,
            total_inconclusive: 1,
            critical: 1,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
        };

        let rendered = format!("{}", summary);
        assert!(rendered.contains("Planned Checks"));
        assert!(rendered.contains("Critical"));
        assert!(rendered.contains("High"));
    }

    #[test]
    fn test_with_args_uses_selective_mode_for_specific_flag() {
        let mut request = ScanRequest::default();
        request.scan.scope.all = true;
        request.scan.vulns.heartbleed = true;

        let scanner = VulnerabilityScanner::with_args(dummy_target(), &request);
        assert!(!scanner.broad_scan);
        assert!(
            scanner
                .selected_checks
                .is_enabled(&VulnerabilityType::Heartbleed)
        );
        assert_eq!(scanner.planned_test_count(), 1);
    }

    #[test]
    fn test_with_args_keeps_broad_mode_for_full_scan() {
        let mut request = ScanRequest::default();
        request.scan.scope.full = true;

        let scanner = VulnerabilityScanner::with_args(dummy_target(), &request);
        assert!(scanner.broad_scan);
        assert_eq!(scanner.planned_test_count(), 25);
    }
}
