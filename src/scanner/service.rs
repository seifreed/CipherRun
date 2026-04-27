use super::{RatingResults, ScanMetadata, ScanResults, SniMethod, builders, phases};
use crate::Result;
use crate::application::ScanRequest;
use crate::protocols::pre_handshake::{PreHandshakeScanResult, PreHandshakeScanner};
use crate::rating::{RatingCalculator, RatingResult, grader::Grade};
use crate::scanner::probe_status::{ErrorType, ProbeStatus};
use crate::security::input_validation::validate_resolved_ips;
use crate::utils::custom_resolvers::CustomResolver;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::{Target, canonical_target, split_target_host_port};
use crate::utils::network_runtime;
use crate::utils::reverse_ptr::ReversePtrLookup;
use crate::utils::sni_generator::SniGenerator;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Sentinel IP used as placeholder before async DNS resolution in `initialize()`.
const PLACEHOLDER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

/// Main scanner struct
///
/// Now Send + Sync compatible for parallel async execution via tokio::spawn.
/// Uses Arc<RwLock<Target>> for interior mutability to allow &self methods.
///
/// The reporter field follows Dependency Inversion: the Scanner (domain layer)
/// depends on the `ScanProgressReporter` abstraction rather than a concrete
/// presentation layer class like `TerminalProgressReporter`.
pub struct Scanner {
    pub request: ScanRequest,
    target: Arc<RwLock<Target>>,
    mtls_config: Option<MtlsConfig>,
    pub(super) reporter: Arc<dyn phases::ScanProgressReporter>,
}

struct PreflightCapture {
    probe_status: ProbeStatus,
    pre_handshake: Option<PreHandshakeScanResult>,
}

impl Scanner {
    /// Create a new Scanner with the default TerminalProgressReporter
    ///
    /// This is the primary constructor for CLI usage where terminal output is desired.
    /// For headless/API operation, use `with_reporter()` with a `SilentProgressReporter`.
    pub fn new(request: ScanRequest) -> Result<Self> {
        Self::with_reporter(request, Arc::new(phases::TerminalProgressReporter::new()))
    }

    /// Create a new Scanner with a custom progress reporter
    ///
    /// This constructor follows Dependency Inversion by accepting the reporter as a parameter,
    /// allowing the caller to inject different reporters for different contexts:
    /// - `TerminalProgressReporter`: CLI usage with colored terminal output
    /// - `SilentProgressReporter`: API/headless operation with no output
    /// - Custom reporters: Testing, logging, or alternative output formats
    pub fn with_reporter(
        request: ScanRequest,
        reporter: Arc<dyn phases::ScanProgressReporter>,
    ) -> Result<Self> {
        request.validate_for_scan()?;
        let target_str =
            request
                .target
                .as_ref()
                .ok_or_else(|| crate::error::TlsError::InvalidInput {
                    message: "No target specified".into(),
                })?;

        // Use a placeholder target with sentinel IP (0.0.0.0) since DNS resolution requires async.
        // The actual IPs are resolved in initialize() which is called by run() before any scanning.
        let (hostname, embedded_port) = split_target_host_port(target_str)?;
        let placeholder_ip = PLACEHOLDER_IP;
        let target = Target::with_ips(
            hostname,
            request.port.or(embedded_port).unwrap_or(443),
            vec![placeholder_ip],
        )?;

        let mtls_config = if let (Some(key_path), Some(cert_path)) =
            (&request.tls.client_key, &request.tls.client_certs)
        {
            Some(MtlsConfig::from_separate_files(
                cert_path,
                key_path,
                request.tls.client_key_password.as_deref(),
            )?)
        } else if let Some(mtls_path) = &request.tls.mtls_cert {
            Some(MtlsConfig::from_pem_file(mtls_path)?)
        } else {
            None
        };

        Ok(Self {
            request,
            target: Arc::new(RwLock::new(target)),
            mtls_config,
            reporter,
        })
    }

    /// Initialize target with DNS resolution
    pub async fn initialize(&self) -> Result<()> {
        let target_str =
            self.request
                .target
                .as_ref()
                .ok_or_else(|| crate::error::TlsError::InvalidInput {
                    message: "No target specified".into(),
                })?;

        let parsed_target = if let Some(ip_override) = self.request.ip.as_deref() {
            let ip: IpAddr =
                ip_override
                    .parse()
                    .map_err(|_| crate::error::TlsError::InvalidInput {
                        message: format!("Invalid IP override: {}", ip_override),
                    })?;
            let (hostname, embedded_port) = split_target_host_port(target_str)?;
            let port = self.request.port.or(embedded_port).unwrap_or(443);
            Target::with_ips(hostname, port, vec![ip])?
        } else {
            self.resolve_target_with_request_network(target_str).await?
        };
        *self.target.write() = parsed_target;
        Ok(())
    }

    /// Get an owned copy of the target
    pub(super) fn get_target_owned(&self) -> Target {
        self.target.read().clone()
    }

    /// Set the target (used by multi-IP scanner to override target for single IP scans)
    pub fn set_target(&self, target: Target) {
        *self.target.write() = target;
    }

    /// Run complete scan using phase-based orchestration
    pub async fn run_with_phases(&self) -> Result<ScanResults> {
        network_runtime::scope_proxy(
            self.request.network.proxy.clone(),
            self.run_with_phases_inner(),
        )
        .await
    }

    async fn run_with_phases_inner(&self) -> Result<ScanResults> {
        let start_time = Instant::now();

        let placeholder_ip = PLACEHOLDER_IP;
        let needs_init = {
            let target = self.target.read();
            target.ip_addresses.len() == 1 && target.ip_addresses[0] == placeholder_ip
        };
        if needs_init && let Err(error) = self.initialize().await {
            if self.request.scan.prefs.probe_status {
                return Ok(self.build_probe_only_results(
                    ProbeStatus::failure_string(
                        error.to_string(),
                        ErrorType::from_tls_error(&error),
                    ),
                    start_time.elapsed().as_millis() as u64,
                    false,
                ));
            }
            return Err(error);
        }

        let should_run_multi_ip = {
            let target = self.target.read();
            target.ip_addresses.len() > 1 && !self.request.network.first_ip_only
        };

        if should_run_multi_ip {
            return self.run_multi_ip_scan().await;
        }

        let preflight = self.collect_preflight_capture().await?;

        let target = self.get_target_owned();
        let (request, sni_used, sni_generation_method) =
            self.request_with_effective_sni(&target).await;

        let mut context = builders::build_scan_context(
            target,
            request,
            self.mtls_config.clone(),
            preflight
                .as_ref()
                .and_then(|capture| capture.pre_handshake.clone()),
        );
        context.results.scan_metadata.sni_used = sni_used;
        context.results.scan_metadata.sni_generation_method = sni_generation_method;
        if let Some(preflight) = &preflight {
            context.results.scan_metadata.probe_status = preflight.probe_status.clone();
            context.results.scan_metadata.pre_handshake_used = preflight.pre_handshake.is_some();
        }
        let orchestrator = builders::build_phase_orchestrator(self.reporter.clone());

        let results = orchestrator.execute(context).await?;

        Ok(self.finalize_scan_results(results, start_time, &preflight))
    }

    fn finalize_scan_results(
        &self,
        mut results: ScanResults,
        start_time: Instant,
        preflight: &Option<PreflightCapture>,
    ) -> ScanResults {
        if self.request.should_calculate_rating() {
            let rating_result = self.calculate_rating(&results);
            results.rating = Some(RatingResults {
                ssl_rating: Some(rating_result),
            });
        }

        results.scan_time_ms = start_time.elapsed().as_millis() as u64;
        if let Some(preflight) = preflight {
            results.scan_metadata.probe_status =
                self.reconcile_probe_status(&preflight.probe_status, &results);
            results.scan_metadata.pre_handshake_used = preflight.pre_handshake.is_some();
        }

        results
    }

    /// Run complete scan and return results
    pub async fn run(&self) -> Result<ScanResults> {
        self.run_with_phases().await
    }

    async fn resolve_target_with_request_network(&self, target_str: &str) -> Result<Target> {
        let (hostname, embedded_port) = split_target_host_port(target_str)?;
        let port = self.request.port.or(embedded_port).unwrap_or(443);
        if self.request.network.resolvers.is_empty() {
            return Ok(Target::parse_with_port_override(target_str, self.request.port).await?);
        }

        if let Ok(ip) = hostname.parse::<IpAddr>() {
            validate_resolved_ips(&[ip], false).map_err(|error| crate::TlsError::InvalidInput {
                message: format!("Resolved target failed SSRF validation: {}", error),
            })?;
            return Ok(Target::with_ips(hostname, port, vec![ip])?);
        }

        let resolver = CustomResolver::new(self.request.network.resolvers.clone())?;
        let ips = resolver.resolve(&hostname).await.map_err(|error| {
            crate::TlsError::Other(format!(
                "Custom resolver lookup failed for {}: {}",
                hostname, error
            ))
        })?;
        validate_resolved_ips(&ips, false).map_err(|error| crate::TlsError::InvalidInput {
            message: format!("Resolved target failed SSRF validation: {}", error),
        })?;
        Ok(Target::with_ips(hostname, port, ips)?)
    }

    fn calculate_rating(&self, results: &ScanResults) -> RatingResult {
        let cert_validation = results.certificate_chain.as_ref().map(|c| &c.validation);

        let mut rating = RatingCalculator::calculate(
            &results.protocols,
            &results.ciphers,
            cert_validation,
            &results.vulnerabilities,
        );

        // If certificate data is missing on a full scan, override to Grade T
        // (cannot verify trust without certificate information)
        if cert_validation.is_none() && self.request.should_run_certificate_phase() {
            rating.grade = Grade::T;
        }

        rating
    }

    fn preflight_timeout(&self) -> Duration {
        Duration::from_secs(
            self.request
                .connection
                .connect_timeout
                .or(self.request.connection.socket_timeout)
                .unwrap_or(10)
                .max(1),
        )
    }

    async fn collect_preflight_capture(&self) -> Result<Option<PreflightCapture>> {
        if !self.request.should_collect_preflight_data() {
            return Ok(None);
        }

        let timeout_duration = self.preflight_timeout();
        let target = self.get_target_owned();

        if self.request.scan.prefs.pre_handshake || self.request.scan.certs.ocsp {
            let scanner = PreHandshakeScanner::new(target).with_timeout(timeout_duration);
            match scanner.scan_pre_handshake().await {
                Ok(pre_handshake) => {
                    return Ok(Some(PreflightCapture {
                        probe_status: ProbeStatus::success(Duration::from_millis(
                            pre_handshake.handshake_time_ms,
                        )),
                        pre_handshake: Some(pre_handshake),
                    }));
                }
                Err(error) => {
                    tracing::debug!("Preflight pre-handshake capture failed: {}", error);
                    if self.request.scan.prefs.probe_status {
                        return Ok(Some(PreflightCapture {
                            probe_status: ProbeStatus::failure_string(
                                error.to_string(),
                                ErrorType::from_tls_error(&error),
                            ),
                            pre_handshake: None,
                        }));
                    }
                }
            }
        }

        if self.request.scan.prefs.probe_status {
            return Ok(Some(PreflightCapture {
                probe_status: self.probe_connectivity(timeout_duration).await,
                pre_handshake: None,
            }));
        }

        Ok(None)
    }

    async fn probe_connectivity(&self, timeout_duration: Duration) -> ProbeStatus {
        let target = self.get_target_owned();
        let Some(socket_addr) = target.socket_addrs().into_iter().next() else {
            return ProbeStatus::failure_string(
                "No resolved IP address available".to_string(),
                ErrorType::DnsFailure,
            );
        };

        let start = Instant::now();
        match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                ProbeStatus::success(start.elapsed())
            }
            Ok(Err(error)) => {
                ProbeStatus::failure_string(error.to_string(), ErrorType::NetworkError)
            }
            Err(_) => ProbeStatus::failure_string(
                format!("Connection timeout after {:?}", timeout_duration),
                ErrorType::Timeout,
            ),
        }
    }

    fn build_probe_only_results(
        &self,
        probe_status: ProbeStatus,
        scan_time_ms: u64,
        pre_handshake_used: bool,
    ) -> ScanResults {
        let target = self.get_target_owned();

        ScanResults {
            target: canonical_target(&target.hostname, target.port),
            scan_time_ms,
            scan_metadata: ScanMetadata {
                probe_status,
                pre_handshake_used,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    async fn request_with_effective_sni(
        &self,
        target: &Target,
    ) -> (ScanRequest, Option<String>, Option<SniMethod>) {
        let (resolved_sni, method) = self.resolve_effective_sni(target).await;
        let mut request = self.request.clone();
        request.tls.sni_name = resolved_sni.clone();
        (request, resolved_sni, method)
    }

    async fn resolve_effective_sni(&self, target: &Target) -> (Option<String>, Option<SniMethod>) {
        if let Some(explicit_sni) = self.request.tls.sni_name.clone() {
            return (
                Some(explicit_sni.clone()),
                Some(SniMethod::Custom(explicit_sni)),
            );
        }

        if target.hostname.parse::<IpAddr>().is_err() {
            return (Some(target.hostname.clone()), Some(SniMethod::Hostname));
        }

        let ip = target.primary_ip();
        if self.request.tls.reverse_ptr_sni
            && matches!(
                ReversePtrLookup::validate_ptr_forward_match(&ip).await,
                Ok(true)
            )
            && let Ok(ptr_hostname) = ReversePtrLookup::lookup_ptr(&ip).await
        {
            return (Some(ptr_hostname), Some(SniMethod::ReversePTR));
        }

        if self.request.tls.random_sni {
            return (
                Some(SniGenerator::generate_random()),
                Some(SniMethod::Random),
            );
        }

        (None, None)
    }

    fn reconcile_probe_status(
        &self,
        preflight: &ProbeStatus,
        results: &ScanResults,
    ) -> ProbeStatus {
        if preflight.success || !results.has_connection_evidence() {
            return preflight.clone();
        }

        ProbeStatus {
            success: true,
            error: Some(
                "Preflight probe failed but later scan phases completed successfully".to_string(),
            ),
            error_type: Some(ErrorType::Warning),
            connection_time_ms: preflight.connection_time_ms,
            attempts: preflight.attempts.max(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::scan_request::ScanRequestScan;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::scanner::SilentProgressReporter;
    use std::sync::Arc;

    fn test_scanner() -> Scanner {
        Scanner::new(ScanRequest {
            target: Some("example.com:443".to_string()),
            scan: crate::application::scan_request::ScanRequestScan {
                prefs: crate::application::scan_request::ScanRequestPrefs {
                    probe_status: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("scanner should build")
    }

    #[test]
    fn reconcile_probe_status_keeps_successful_preflight() {
        let scanner = test_scanner();
        let preflight = ProbeStatus::success(Duration::from_millis(15));
        let reconciled = scanner.reconcile_probe_status(&preflight, &ScanResults::default());

        assert!(reconciled.success);
        assert_eq!(reconciled.connection_time_ms, Some(15));
    }

    #[test]
    fn reconcile_probe_status_upgrades_failure_when_later_phases_succeed() {
        let scanner = test_scanner();
        let preflight =
            ProbeStatus::failure_string("Connection refused".to_string(), ErrorType::NetworkError);
        let mut results = ScanResults::default();
        results.protocols.push(ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            inconclusive: false,
            preferred: true,
            ciphers_count: 1,
            handshake_time_ms: Some(5),
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        });

        let reconciled = scanner.reconcile_probe_status(&preflight, &results);

        assert!(reconciled.success);
        assert_eq!(reconciled.error_type, Some(ErrorType::Warning));
    }

    #[test]
    fn reconcile_probe_status_preserves_failure_without_network_evidence() {
        let scanner = test_scanner();
        let preflight =
            ProbeStatus::failure_string("Connection refused".to_string(), ErrorType::NetworkError);
        let reconciled = scanner.reconcile_probe_status(&preflight, &ScanResults::default());

        assert!(!reconciled.success);
        assert_eq!(reconciled.error_type, Some(ErrorType::NetworkError));
    }

    #[test]
    fn reconcile_probe_status_upgrades_failure_when_only_vulnerability_results_exist() {
        let scanner = test_scanner();
        let preflight =
            ProbeStatus::failure_string("Connection refused".to_string(), ErrorType::NetworkError);
        let results = ScanResults {
            vulnerabilities: vec![crate::vulnerabilities::VulnerabilityResult {
                vuln_type: crate::vulnerabilities::VulnerabilityType::ROBOT,
                vulnerable: false,
                inconclusive: false,
                details: "Not vulnerable".to_string(),
                cve: None,
                cwe: None,
                severity: crate::vulnerabilities::Severity::Info,
            }],
            ..Default::default()
        };

        let reconciled = scanner.reconcile_probe_status(&preflight, &results);

        assert!(reconciled.success);
        assert_eq!(reconciled.error_type, Some(ErrorType::Warning));
    }

    #[tokio::test]
    async fn initialize_preserves_explicit_cli_port_override() {
        let scanner = Scanner::with_reporter(
            ScanRequest {
                target: Some("93.184.216.34:443".to_string()),
                port: Some(8443),
                scan: ScanRequestScan {
                    prefs: crate::application::scan_request::ScanRequestPrefs {
                        probe_status: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            Arc::new(SilentProgressReporter::new()),
        )
        .expect("scanner should build");

        scanner
            .initialize()
            .await
            .expect("initialization should succeed");

        let target = scanner.get_target_owned();
        assert_eq!(target.hostname, "93.184.216.34");
        assert_eq!(target.port, 8443);
    }

    #[tokio::test]
    async fn initialize_uses_ip_override_without_re_resolving_hostname() {
        let scanner = Scanner::with_reporter(
            ScanRequest {
                target: Some("example.com:443".to_string()),
                ip: Some("198.51.100.20".to_string()),
                scan: ScanRequestScan {
                    prefs: crate::application::scan_request::ScanRequestPrefs {
                        probe_status: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            Arc::new(SilentProgressReporter::new()),
        )
        .expect("scanner should build");

        scanner
            .initialize()
            .await
            .expect("initialization should succeed");

        let target = scanner.get_target_owned();
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(
            target.ip_addresses,
            vec!["198.51.100.20".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn resolved_sni_uses_hostname_for_ip_override_scans() {
        let scanner = Scanner::with_reporter(
            ScanRequest {
                target: Some("example.com:443".to_string()),
                ip: Some("198.51.100.20".to_string()),
                scan: ScanRequestScan {
                    prefs: crate::application::scan_request::ScanRequestPrefs {
                        probe_status: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            Arc::new(SilentProgressReporter::new()),
        )
        .expect("scanner should build");

        scanner
            .initialize()
            .await
            .expect("initialization should succeed");

        let target = scanner.get_target_owned();
        let (_request, sni_used, method) = scanner.request_with_effective_sni(&target).await;

        assert_eq!(sni_used.as_deref(), Some("example.com"));
        assert!(matches!(method, Some(SniMethod::Hostname)));
    }
}
