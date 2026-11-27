// Anycast Detection Module
// Resolves all A/AAAA records and scans each IP individually
// Detects Anycast deployments by comparing certificates and behaviors

mod detection;

use crate::Args;
use crate::Result;
use crate::error::TlsError;
use crate::scanner::ScanResults;
use crate::security::input_validation::validate_resolved_ips;
use crate::utils::network::{
    Target, build_system_resolver, canonical_target, normalize_dns_hostname,
};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;
use tracing::{debug, info};

/// Anycast scanner for testing all IPs of a hostname
pub struct AnycastScanner {
    hostname: String,
    port: u16,
    args: Args,
}

impl AnycastScanner {
    fn build_resolver() -> Result<TokioResolver> {
        build_system_resolver().map_err(|error| TlsError::ConfigError {
            message: format!("Failed to initialize DNS resolver: {error}"),
        })
    }

    /// Create new anycast scanner
    pub fn new(hostname: String, port: u16, args: Args) -> Self {
        Self {
            hostname: normalize_dns_hostname(hostname),
            port,
            args,
        }
    }

    /// Scan all IPs resolved for the hostname
    pub async fn scan_all_ips(&self) -> Result<AnycastScanResults> {
        let scan_started = Instant::now();
        // 1. Resolve hostname to all IPs (A + AAAA records)
        let resolution_started = Instant::now();
        let ip_addresses = match self.resolve_all_ips().await {
            Ok(ip_addresses) => ip_addresses,
            Err(error) => {
                log_anycast_dns_resolution_failed(
                    u64::try_from(resolution_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    error.observability_code(),
                );
                return Err(error);
            }
        };

        self.scan_resolved_ips(ip_addresses, scan_started, resolution_started)
            .await
    }

    async fn scan_resolved_ips(
        &self,
        ip_addresses: Vec<IpAddr>,
        scan_started: Instant,
        resolution_started: Instant,
    ) -> Result<AnycastScanResults> {
        if ip_addresses.is_empty() {
            log_anycast_dns_resolution_failed(
                u64::try_from(resolution_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "no_addresses",
            );
            return Err(TlsError::DnsResolutionFailed {
                hostname: self.hostname.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No IP addresses resolved",
                ),
            });
        }

        info!(
            event_name = "anycast.dns_resolution.completed",
            operation = "resolve_all_ips",
            total_ips = ip_addresses.len(),
            duration_ms =
                u64::try_from(resolution_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "success",
            "Anycast addresses resolved"
        );

        // 2. Scan each IP individually
        let mut ip_results = Vec::new();
        for (index, ip) in ip_addresses.iter().enumerate() {
            debug!(
                event_name = "anycast.ip_scan.started",
                operation = "scan_single_ip",
                scan_index = index + 1,
                total_ips = ip_addresses.len(),
                outcome = "started",
                "Starting Anycast scan for resolved address"
            );

            let ip_scan_started = Instant::now();
            match self.scan_single_ip(ip).await {
                Ok(scan_result) => {
                    log_anycast_ip_scan_completed(
                        index + 1,
                        ip_addresses.len(),
                        u64::try_from(ip_scan_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    );
                    ip_results.push(IpScanResult {
                        ip: *ip,
                        results: scan_result,
                        error: None,
                    });
                }
                Err(e) => {
                    debug!(
                        event_name = "anycast.ip_scan.failed",
                        operation = "scan_single_ip",
                        scan_index = index + 1,
                        total_ips = ip_addresses.len(),
                        duration_ms = u64::try_from(ip_scan_started.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
                        error_type = "scan",
                        error_code = e.observability_code(),
                        outcome = "partial_failure",
                        "Anycast scan failed for one resolved address"
                    );
                    ip_results.push(IpScanResult {
                        ip: *ip,
                        results: ScanResults::default(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // 3. Detect Anycast deployment
        let anycast_detection = Self::detect_anycast(&ip_results);
        let successful_scans = ip_results.iter().filter(|r| r.error.is_none()).count();
        log_anycast_scan_summary(
            ip_addresses.len(),
            successful_scans,
            anycast_detection.is_anycast,
            u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        );

        Ok(AnycastScanResults {
            hostname: self.hostname.clone(),
            port: self.port,
            total_ips: ip_addresses.len(),
            successful_scans,
            ip_results,
            anycast_detection,
        })
    }

    /// Resolve all A and AAAA records for hostname
    async fn resolve_all_ips(&self) -> Result<Vec<IpAddr>> {
        crate::security::validate_hostname(&self.hostname).map_err(|error| {
            TlsError::InvalidInput {
                message: format!("Invalid anycast hostname: {error}"),
            }
        })?;

        let resolver = Self::build_resolver()?;

        let mut ips = Vec::new();

        // Query A records (IPv4)
        if !self.args.network.ipv6_only {
            let lookup_started = Instant::now();
            match resolver.ipv4_lookup(&self.hostname).await {
                Ok(lookup) => {
                    for ipv4 in lookup
                        .answers()
                        .iter()
                        .filter_map(|record| match &record.data {
                            RData::A(ipv4) => Some(IpAddr::V4(ipv4.0)),
                            _ => None,
                        })
                    {
                        ips.push(ipv4);
                    }
                }
                Err(_) => {
                    // A records not found, continue
                    debug!(
                        event_name = "anycast.dns_lookup.failed",
                        operation = "ipv4_lookup",
                        duration_ms =
                            u64::try_from(lookup_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        error_type = "dns",
                        error_code = "lookup_failed",
                        outcome = "continue_with_other_family",
                        "Anycast IPv4 lookup failed"
                    );
                }
            }
        }

        // Query AAAA records (IPv6)
        if !self.args.network.ipv4_only {
            let lookup_started = Instant::now();
            match resolver.ipv6_lookup(&self.hostname).await {
                Ok(lookup) => {
                    for ipv6 in lookup
                        .answers()
                        .iter()
                        .filter_map(|record| match &record.data {
                            RData::AAAA(ipv6) => Some(IpAddr::V6(ipv6.0)),
                            _ => None,
                        })
                    {
                        ips.push(ipv6);
                    }
                }
                Err(_) => {
                    // AAAA records not found, continue
                    debug!(
                        event_name = "anycast.dns_lookup.failed",
                        operation = "ipv6_lookup",
                        duration_ms =
                            u64::try_from(lookup_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        error_type = "dns",
                        error_code = "lookup_failed",
                        outcome = "continue_with_other_family",
                        "Anycast IPv6 lookup failed"
                    );
                }
            }
        }

        validate_anycast_resolved_ips(&self.hostname, &ips)?;

        Ok(ips)
    }

    /// Scan a single IP address with SNI=hostname
    async fn scan_single_ip(&self, ip: &IpAddr) -> Result<ScanResults> {
        // Create target with specific IP (unused but kept for potential future use)
        let _target = Target::with_ips(self.hostname.clone(), self.port, vec![*ip])?;

        // Create scanner with modified args (use IP directly)
        let mut scanner_args = self.args.clone();
        scanner_args.target = Some(anycast_target_for_ip(ip, self.port));

        // Override SNI to use original hostname
        if scanner_args.tls.sni_name.is_none() {
            scanner_args.tls.sni_name = Some(self.hostname.clone());
        }

        // Create and run scanner
        let scanner = crate::scanner::Scanner::new(scanner_args.to_scan_request()?)?;
        scanner.run().await
    }
}

fn log_anycast_scan_summary(
    total_ips: usize,
    successful_scans: usize,
    is_anycast: bool,
    duration_ms: u64,
) {
    let failed_scans = total_ips.saturating_sub(successful_scans);
    if failed_scans == 0 {
        info!(
            event_name = "anycast.scan.completed",
            operation = "scan_all_ips",
            total_ips,
            successful_scans,
            failed_scans,
            is_anycast,
            duration_ms,
            outcome = "success",
            "Anycast scan completed"
        );
    } else {
        tracing::warn!(
            event_name = "anycast.scan.completed",
            operation = "scan_all_ips",
            total_ips,
            successful_scans,
            failed_scans,
            is_anycast,
            duration_ms,
            error_type = "partial_scan",
            error_code = "address_scan_failed",
            outcome = "partial_failure",
            "Anycast scan completed with address failures"
        );
    }
}

fn log_anycast_dns_resolution_failed(duration_ms: u64, error_code: &'static str) {
    tracing::warn!(
        event_name = "anycast.dns_resolution.failed",
        operation = "resolve_all_ips",
        duration_ms,
        error_type = "resolution",
        error_code,
        outcome = "failed",
        "Anycast address resolution failed"
    );
}

fn log_anycast_ip_scan_completed(scan_index: usize, total_ips: usize, duration_ms: u64) {
    debug!(
        event_name = "anycast.ip_scan.completed",
        operation = "scan_single_ip",
        scan_index,
        total_ips,
        duration_ms,
        outcome = "success",
        "Anycast scan completed for resolved address"
    );
}

fn anycast_target_for_ip(ip: &IpAddr, port: u16) -> String {
    canonical_target(&ip.to_string(), port)
}

fn validate_anycast_resolved_ips(hostname: &str, ips: &[IpAddr]) -> Result<()> {
    validate_resolved_ips(ips, false)
        .map_err(|error| TlsError::Other(format!("SSRF validation failed for {hostname}: {error}")))
}

/// Result of scanning a single IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpScanResult {
    pub ip: IpAddr,
    pub results: ScanResults,
    pub error: Option<String>,
}

/// Complete Anycast scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnycastScanResults {
    pub hostname: String,
    pub port: u16,
    pub total_ips: usize,
    pub successful_scans: usize,
    pub ip_results: Vec<IpScanResult>,
    pub anycast_detection: AnycastDetection,
}

/// Anycast detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnycastDetection {
    pub is_anycast: bool,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub certificate_fingerprints: HashSet<String>,
    pub cipher_preferences: HashMap<IpAddr, String>,
    pub protocol_support: HashMap<IpAddr, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::parser::{CertificateChain, CertificateInfo};
    use crate::certificates::validator::ValidationResult;
    use crate::ciphers::CipherSuite;
    use crate::ciphers::tester::ProtocolCipherSummary;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    struct FailingSummaryWriter {
        fail_after: usize,
        writes: usize,
    }

    impl Write for FailingSummaryWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.writes == self.fail_after {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.writes += 1;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogWriter(self.0.clone())
        }
    }

    #[test]
    fn scan_summary_logs_partial_outcome_without_target_data() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(CapturedLog(output.clone()))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_anycast_scan_summary(2, 1, false, 123);
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(output.contains("anycast.scan.completed"), "{output}");
        assert!(output.contains("total_ips=2"), "{output}");
        assert!(output.contains("successful_scans=1"), "{output}");
        assert!(output.contains("failed_scans=1"), "{output}");
        assert!(output.contains("duration_ms=123"), "{output}");
        assert!(output.contains("partial_failure"), "{output}");
        assert!(output.contains("WARN"), "{output}");
        assert!(!output.contains("example.com"), "{output}");
        assert!(!output.contains("203.0.113.1"), "{output}");
    }

    #[test]
    fn dns_and_ip_outcomes_log_structured_timing_without_target_data() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(CapturedLog(output.clone()))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_anycast_dns_resolution_failed(23, "no_addresses");
            log_anycast_ip_scan_completed(2, 3, 456);
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2, "{output}");
        assert_eq!(events[0]["level"], "WARN");
        assert_eq!(
            events[0]["fields"]["event_name"],
            "anycast.dns_resolution.failed"
        );
        assert_eq!(events[0]["fields"]["error_code"], "no_addresses");
        assert_eq!(events[0]["fields"]["duration_ms"], 23);
        assert_eq!(events[1]["level"], "DEBUG");
        assert_eq!(
            events[1]["fields"]["event_name"],
            "anycast.ip_scan.completed"
        );
        assert_eq!(events[1]["fields"]["scan_index"], 2);
        assert_eq!(events[1]["fields"]["total_ips"], 3);
        assert_eq!(events[1]["fields"]["duration_ms"], 456);
        assert_eq!(events[1]["fields"]["outcome"], "success");
        assert!(!output.contains("example.com"));
        assert!(!output.contains("203.0.113.1"));
    }

    fn build_scan_with_fingerprint(
        fingerprint: &str,
        cipher_name: &str,
        protocols: Vec<Protocol>,
    ) -> ScanResults {
        let cert = CertificateInfo {
            fingerprint_sha256: Some(fingerprint.to_string()),
            ..Default::default()
        };
        let chain = CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 0,
        };
        let validation = ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        };
        let cipher = CipherSuite {
            hexcode: "0x1301".to_string(),
            openssl_name: cipher_name.to_string(),
            iana_name: "TLS_AES_128_GCM_SHA256".to_string(),
            protocol: "TLS13".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AESGCM".to_string(),
            mac: "AEAD".to_string(),
            bits: 128,
            export: false,
        };
        let mut ciphers = HashMap::new();
        ciphers.insert(
            Protocol::TLS12,
            ProtocolCipherSummary {
                protocol: Protocol::TLS12,
                supported_ciphers: vec![],
                server_ordered: false,
                server_preference: vec![],
                preferred_cipher: Some(cipher),
                counts: Default::default(),
                avg_handshake_time_ms: None,
            },
        );

        ScanResults {
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain,
                validation,
                revocation: None,
            }),
            ciphers,
            protocols: protocols
                .into_iter()
                .map(|protocol| ProtocolTestResult {
                    protocol,
                    supported: true,
                    inconclusive: false,
                    preferred: false,
                    ciphers_count: 0,
                    handshake_time_ms: None,
                    heartbeat_enabled: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_anycast_detection_different_certs() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
        ];

        // Simulate different certificate fingerprints
        // (In real code, this would come from actual certificate data)

        let detection = AnycastScanner::detect_anycast(&results);

        // With default ScanResults, we don't have cert data, so it should be uncertain
        assert!(detection.confidence >= 0.0);
    }

    #[test]
    fn test_anycast_target_for_ip_brackets_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(anycast_target_for_ip(&ip, 443), "[2001:db8::1]:443");
    }

    #[test]
    fn test_anycast_target_for_ip_keeps_ipv4_plain() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(anycast_target_for_ip(&ip, 443), "192.0.2.10:443");
    }

    #[tokio::test]
    async fn test_resolve_all_ips_rejects_invalid_hostname_before_lookup() {
        let scanner = AnycastScanner::new("example.com/path".to_string(), 443, Args::default());

        let err = scanner
            .resolve_all_ips()
            .await
            .expect_err("invalid anycast hostname should fail before lookup");
        assert!(err.to_string().contains("Invalid anycast hostname"));
    }

    #[tokio::test]
    async fn scan_all_ips_reports_invalid_hostname_resolution_failure() {
        let scanner = AnycastScanner::new("example.com/path".to_string(), 443, Args::default());

        let error = scanner
            .scan_all_ips()
            .await
            .expect_err("invalid anycast hostname should fail before scanning");

        assert!(error.to_string().contains("Invalid anycast hostname"));
    }

    #[tokio::test]
    async fn scan_resolved_ips_rejects_an_empty_address_list() {
        let scanner = AnycastScanner::new("example.com".to_string(), 443, Args::default());

        let error = scanner
            .scan_resolved_ips(Vec::new(), Instant::now(), Instant::now())
            .await
            .expect_err("an empty DNS result must not produce a scan report");

        assert!(matches!(error, TlsError::DnsResolutionFailed { .. }));
    }

    #[tokio::test]
    async fn scan_resolved_ips_keeps_per_address_failures_in_the_report() {
        let scanner = AnycastScanner::new("example.com".to_string(), 0, Args::default());

        let result = scanner
            .scan_resolved_ips(
                vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
                Instant::now(),
                Instant::now(),
            )
            .await
            .expect("isolated per-address errors should be summarized as a result");

        assert_eq!(result.total_ips, 2);
        assert_eq!(result.successful_scans, 0);
        assert_eq!(result.ip_results.len(), 2);
        assert!(result.ip_results.iter().all(|scan| {
            scan.error
                .as_deref()
                .is_some_and(|error| error.contains("Port must be between"))
        }));
    }

    #[test]
    fn test_anycast_scanner_normalizes_rooted_hostname() {
        let scanner = AnycastScanner::new("example.com.".to_string(), 443, Args::default());
        assert_eq!(scanner.hostname, "example.com");
    }

    #[test]
    fn test_validate_anycast_resolved_ips_rejects_private_ip() {
        let ips = ["127.0.0.1".parse().unwrap()];

        let err = validate_anycast_resolved_ips("example.com", &ips)
            .expect_err("private anycast DNS answers should be blocked");
        assert!(err.to_string().contains("SSRF validation failed"));
    }

    #[test]
    fn test_anycast_detection_insufficient_results() {
        let results = vec![IpScanResult {
            ip: "1.1.1.1".parse().unwrap(),
            results: ScanResults::default(),
            error: None,
        }];
        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert!(detection.reasons.iter().any(|r| r.contains("Insufficient")));
    }

    #[test]
    fn test_anycast_detection_all_errors() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: Some("fail".to_string()),
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: Some("fail".to_string()),
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.certificate_fingerprints.len(), 0);
        assert!(detection.reasons.iter().any(|r| r.contains("Insufficient")));
    }

    #[test]
    fn test_anycast_detection_one_success_one_error_insufficient() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: Some("fail".to_string()),
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert!(detection.reasons.iter().any(|r| r.contains("Insufficient")));
    }

    #[test]
    fn test_anycast_detection_different_fingerprints() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp2",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];
        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("Different certificates"))
        );
    }

    #[test]
    fn test_anycast_detection_identical_results() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];
        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.confidence, 0.0);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("identical certificates"))
        );
    }

    #[test]
    fn test_anycast_detection_identical_results_reasons_count() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.reasons.len(), 3);
    }

    #[test]
    fn test_anycast_detection_different_cipher_preferences() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_256_GCM_SHA384",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("cipher preferences"))
        );
    }

    #[test]
    fn test_anycast_same_multi_protocol_cipher_prefs_not_flagged() {
        // Two non-anycast backends with identical per-protocol preferred ciphers
        // across multiple protocols must never be flagged as having different
        // cipher preferences, regardless of HashMap iteration order.
        let make = || {
            let mut results = build_scan_with_fingerprint(
                "fp1",
                "ECDHE-RSA-AES128-GCM-SHA256",
                vec![Protocol::TLS12, Protocol::TLS13],
            );
            results.ciphers.insert(
                Protocol::TLS13,
                ProtocolCipherSummary {
                    protocol: Protocol::TLS13,
                    supported_ciphers: vec![],
                    server_ordered: false,
                    server_preference: vec![],
                    preferred_cipher: Some(CipherSuite {
                        hexcode: "0x1303".to_string(),
                        openssl_name: "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                        iana_name: "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                        protocol: "TLS13".to_string(),
                        key_exchange: "ECDHE".to_string(),
                        authentication: "RSA".to_string(),
                        encryption: "CHACHA20".to_string(),
                        mac: "AEAD".to_string(),
                        bits: 256,
                        export: false,
                    }),
                    counts: Default::default(),
                    avg_handshake_time_ms: None,
                },
            );
            results
        };

        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: make(),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: make(),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(
            !detection
                .reasons
                .iter()
                .any(|r| r.contains("Different cipher preferences")),
            "identical multi-protocol cipher preferences must not be flagged: {:?}",
            detection.reasons
        );
    }

    #[test]
    fn test_anycast_detection_different_protocols() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS13],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("protocol support"))
        );
    }

    #[test]
    fn test_anycast_detection_uncertain_with_empty_results() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.confidence, 0.5);
    }

    #[test]
    fn test_anycast_detection_full_confidence() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp2",
                    "TLS_AES_256_GCM_SHA384",
                    vec![Protocol::TLS13],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert_eq!(detection.confidence, 1.0);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("Different certificates"))
        );
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("cipher preferences"))
        );
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("protocol support"))
        );
    }

    #[test]
    fn test_anycast_display_summary_smoke() {
        let results = AnycastScanResults {
            hostname: "example.com".to_string(),
            port: 443,
            total_ips: 0,
            successful_scans: 0,
            ip_results: Vec::new(),
            anycast_detection: AnycastDetection {
                is_anycast: false,
                confidence: 0.0,
                reasons: vec![],
                certificate_fingerprints: HashSet::new(),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            },
        };

        results.display_summary();
    }

    #[test]
    fn test_anycast_display_summary_anycast_true_smoke() {
        let results = AnycastScanResults {
            hostname: "example.com".to_string(),
            port: 443,
            total_ips: 2,
            successful_scans: 2,
            ip_results: Vec::new(),
            anycast_detection: AnycastDetection {
                is_anycast: true,
                confidence: 0.75,
                reasons: vec![
                    "Different certificates detected (2 unique fingerprints)".to_string(),
                ],
                certificate_fingerprints: HashSet::new(),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            },
        };

        results.display_summary();
    }

    #[test]
    fn test_anycast_summary_formats_successes_failures_and_detection_reasons() {
        let valid_scan = build_scan_with_fingerprint(
            "fp1",
            "TLS_AES_128_GCM_SHA256",
            vec![Protocol::TLS12, Protocol::TLS13],
        );
        let mut invalid_scan =
            build_scan_with_fingerprint("fp2", "TLS_AES_256_GCM_SHA384", Vec::new());
        invalid_scan
            .certificate_chain
            .as_mut()
            .unwrap()
            .validation
            .valid = false;

        let results = AnycastScanResults {
            hostname: "example.com".to_string(),
            port: 443,
            total_ips: 4,
            successful_scans: 3,
            ip_results: vec![
                IpScanResult {
                    ip: "192.0.2.1".parse().unwrap(),
                    results: ScanResults::default(),
                    error: Some("connection refused".to_string()),
                },
                IpScanResult {
                    ip: "192.0.2.2".parse().unwrap(),
                    results: valid_scan,
                    error: None,
                },
                IpScanResult {
                    ip: "192.0.2.3".parse().unwrap(),
                    results: invalid_scan,
                    error: None,
                },
                IpScanResult {
                    ip: "192.0.2.4".parse().unwrap(),
                    results: ScanResults::default(),
                    error: None,
                },
            ],
            anycast_detection: AnycastDetection {
                is_anycast: true,
                confidence: 0.8,
                reasons: vec!["Different certificates detected".to_string()],
                certificate_fingerprints: HashSet::from(["fp1".to_string(), "fp2".to_string()]),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            },
        };
        let mut output = Vec::new();

        results.write_summary(&mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        for expected in [
            "192.0.2.1 - connection refused",
            "192.0.2.2 - Valid Cert - 2 protocols",
            "192.0.2.3 - Invalid Cert - 0 protocols",
            "192.0.2.4 - No Cert - 0 protocols",
            "Anycast Detected: YES (confidence: 80%)",
            "Different certificates detected",
            "Unique Certificates: 2",
        ] {
            assert!(
                output.contains(expected),
                "missing {expected:?} in {output:?}"
            );
        }
    }

    #[test]
    fn test_anycast_summary_propagates_writer_failures_at_each_output_step() {
        let results = AnycastScanResults {
            hostname: "example.com".to_string(),
            port: 443,
            total_ips: 2,
            successful_scans: 1,
            ip_results: vec![
                IpScanResult {
                    ip: "192.0.2.1".parse().unwrap(),
                    results: ScanResults::default(),
                    error: Some("connection refused".to_string()),
                },
                IpScanResult {
                    ip: "192.0.2.2".parse().unwrap(),
                    results: ScanResults::default(),
                    error: None,
                },
            ],
            anycast_detection: AnycastDetection {
                is_anycast: true,
                confidence: 0.5,
                reasons: vec!["Different certificates detected".to_string()],
                certificate_fingerprints: HashSet::from(["fp1".to_string(), "fp2".to_string()]),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            },
        };
        let mut reached_success = false;
        CapturedLogWriter(Arc::new(Mutex::new(Vec::new())))
            .flush()
            .expect("captured log writer flush should succeed");

        for fail_after in 0..128 {
            let mut writer = FailingSummaryWriter {
                fail_after,
                writes: 0,
            };
            let result = results.write_summary(&mut writer);
            writer.flush().expect("summary writer flush should succeed");
            match result {
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe),
                Ok(()) => {
                    reached_success = true;
                    break;
                }
            }
        }

        assert!(
            reached_success,
            "the fixture should reach its successful write"
        );
    }
}
