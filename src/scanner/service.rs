use super::{RatingResults, ScanMetadata, ScanResults, SniMethod, builders, phases};
use crate::Result;
use crate::application::ScanRequest;
use crate::protocols::pre_handshake::{PreHandshakeScanResult, PreHandshakeScanner};
use crate::rating::{RatingCalculator, RatingResult, grader::Grade};
use crate::scanner::probe_status::{ErrorType, ProbeStatus};
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
/// Uses `Arc<RwLock<Target>>` for interior mutability to allow &self methods.
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
    fn effective_port(request: &ScanRequest, embedded_port: Option<u16>) -> u16 {
        request
            .port
            .or(embedded_port)
            .or_else(|| request.starttls_port())
            .unwrap_or(443)
    }

    fn parse_port_override(request: &ScanRequest, embedded_port: Option<u16>) -> Option<u16> {
        request.port.or_else(|| {
            embedded_port
                .is_none()
                .then(|| request.starttls_port())
                .flatten()
        })
    }

    /// Create a new Scanner with the progress reporter implied by the request.
    ///
    /// CLI usage gets the `TerminalProgressReporter`, except in machine-readable
    /// output modes (`--dns`, `--response-only`) where progress would pollute
    /// stdout — those use the `SilentProgressReporter`. For headless/API
    /// operation, use `with_reporter()` with a `SilentProgressReporter`.
    pub fn new(request: ScanRequest) -> Result<Self> {
        let reporter: Arc<dyn phases::ScanProgressReporter> =
            if request.presentation_mode.suppresses_progress() {
                Arc::new(phases::SilentProgressReporter::new())
            } else {
                Arc::new(phases::TerminalProgressReporter::new())
            };
        Self::with_reporter(request, reporter)
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
            Self::effective_port(&request, embedded_port),
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
            Some(MtlsConfig::from_pem_file_with_password(
                mtls_path,
                request.tls.client_key_password.as_deref(),
            )?)
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
        let started = Instant::now();
        let resolution_mode = if self.request.ip.is_some() {
            "ip_override"
        } else if self.request.network.resolvers.is_empty() {
            "system_resolver"
        } else {
            "custom_resolver"
        };
        let initialized: Result<Target> = async {
            let target_str = self.request.target.as_ref().ok_or_else(|| {
                crate::error::TlsError::InvalidInput {
                    message: "No target specified".into(),
                }
            })?;

            if let Some(ip_override) = self.request.ip.as_deref() {
                let ip: IpAddr =
                    ip_override
                        .parse()
                        .map_err(|_| crate::error::TlsError::InvalidInput {
                            message: format!("Invalid IP override: {}", ip_override),
                        })?;
                let (hostname, embedded_port) = split_target_host_port(target_str)?;
                let port = Self::effective_port(&self.request, embedded_port);
                Target::with_ips(hostname, port, vec![ip])
            } else {
                self.resolve_target_with_request_network(target_str).await
            }
        }
        .await;

        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match initialized {
            Ok(target) => {
                let resolved_address_count = target.ip_addresses.len();
                *self.target.write() = target;
                tracing::info!(
                    event_name = "scanner.target.initialized",
                    operation = "resolve_target",
                    resolution_mode,
                    resolved_address_count,
                    duration_ms,
                    outcome = "success",
                    "Scanner target initialized"
                );
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    event_name = "scanner.target.initialization_failed",
                    operation = "resolve_target",
                    resolution_mode,
                    duration_ms,
                    error_type = "TlsError",
                    error_code = error.observability_code(),
                    outcome = "failed",
                    "Scanner target initialization failed"
                );
                Err(error)
            }
        }
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
            target.ip_addresses.as_slice() == [placeholder_ip]
        };
        if needs_init && let Err(error) = self.initialize().await {
            if self.request.scan.prefs.probe_status {
                return Ok(self.build_probe_only_results(
                    ProbeStatus::failure_string(
                        error.to_string(),
                        ErrorType::from_tls_error(&error),
                    ),
                    u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX),
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
            self.request_with_effective_sni(&target).await?;

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

        results.scan_time_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
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
        let port = Self::effective_port(&self.request, embedded_port);

        let target = if self.request.network.resolvers.is_empty() {
            Target::parse_with_port_override_and_private(
                target_str,
                Self::parse_port_override(&self.request, embedded_port),
                self.request.network.permits_private_resolution(),
            )
            .await?
        } else if let Ok(ip) = hostname.parse::<IpAddr>() {
            self.request.network.validate_resolved_ips(&[ip])?;
            Target::with_ips(hostname, port, vec![ip])?
        } else {
            let resolver = CustomResolver::new(self.request.network.resolvers.clone())?;
            let ips = resolver.resolve(&hostname).await.map_err(|error| {
                crate::TlsError::Other(format!(
                    "Custom resolver lookup failed for {}: {}",
                    hostname, error
                ))
            })?;
            self.request.network.validate_resolved_ips(&ips)?;
            Target::with_ips(hostname, port, ips)?
        };

        self.request
            .network
            .validate_resolved_ips(&target.ip_addresses)?;

        self.apply_address_family_filter(target)
    }

    /// Restrict resolved addresses to the family requested via `-4`/`-6`.
    ///
    /// Without this the `--ipv4-only`/`--ipv6-only` flags are silently ignored
    /// in the single-target scan path: every resolved address (A and AAAA) is
    /// kept, so the scan may connect over the unwanted family.
    fn apply_address_family_filter(&self, mut target: Target) -> Result<Target> {
        let ipv4_only = self.request.network.ipv4_only;
        let ipv6_only = self.request.network.ipv6_only;
        if !ipv4_only && !ipv6_only {
            return Ok(target);
        }

        target.ip_addresses.retain(|ip| {
            if ipv4_only {
                ip.is_ipv4()
            } else {
                ip.is_ipv6()
            }
        });

        if target.ip_addresses.is_empty() {
            let family = if ipv4_only { "IPv4" } else { "IPv6" };
            return Err(crate::TlsError::Other(format!(
                "No {family} addresses resolved for {}",
                target.hostname
            )));
        }

        Ok(target)
    }

    pub(in crate::scanner) fn calculate_rating(&self, results: &ScanResults) -> RatingResult {
        let cert_validation = results.certificate_chain.as_ref().map(|c| &c.validation);

        let mut rating = RatingCalculator::calculate(
            &results.protocols,
            &results.ciphers,
            cert_validation,
            &results.vulnerabilities,
        );

        // If a certificate phase was requested but produced no certificate, the
        // cert could not be retrieved (e.g. handshake/transport failure), so
        // trust is *unknown*. Grade it Unverified — distinct from T ("retrieved
        // and not trusted") — and zero the score to avoid contradictory output
        // such as "Grade Unverified (84/100)".
        if cert_validation.is_none() && self.request.should_run_certificate_phase() {
            rating.grade = Grade::Unverified;
            rating.score = 0;
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
                    tracing::debug!(
                        event_name = "scan.preflight.capture.failed",
                        error_type = ?ErrorType::from_tls_error(&error),
                        "Preflight pre-handshake capture failed"
                    );
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
        let started = Instant::now();
        let target = self.get_target_owned();
        let status = match target.socket_addrs().into_iter().next() {
            Some(socket_addr) => {
                match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        ProbeStatus::success(started.elapsed())
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
            None => ProbeStatus::failure_string(
                "No resolved IP address available".to_string(),
                ErrorType::DnsFailure,
            ),
        };

        tracing::info!(
            event_name = "scan.connectivity_probe.completed",
            operation = "probe_connectivity",
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = if status.success {
                "connected"
            } else {
                "unreachable"
            },
            error_type = ?status.error_type,
            attempts = status.attempts,
            "Connectivity probe completed"
        );
        status
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
    ) -> Result<(ScanRequest, Option<String>, Option<SniMethod>)> {
        let (resolved_sni, method) = self.resolve_effective_sni(target).await?;
        let mut request = self.request.clone();
        request.tls.sni_name = resolved_sni.clone();
        Ok((request, resolved_sni, method))
    }

    async fn resolve_effective_sni(
        &self,
        target: &Target,
    ) -> Result<(Option<String>, Option<SniMethod>)> {
        if let Some(explicit_sni) = self.request.tls.sni_name.clone() {
            return Ok((
                Some(explicit_sni.clone()),
                Some(SniMethod::Custom(explicit_sni)),
            ));
        }

        if target.hostname.parse::<IpAddr>().is_err() {
            return Ok((Some(target.hostname.clone()), Some(SniMethod::Hostname)));
        }

        let ip = target.primary_ip()?;
        if self.request.tls.reverse_ptr_sni
            && matches!(
                ReversePtrLookup::validate_ptr_forward_match(&ip).await,
                Ok(true)
            )
            && let Ok(ptr_hostname) = ReversePtrLookup::lookup_ptr(&ip).await
        {
            return Ok((Some(ptr_hostname), Some(SniMethod::ReversePTR)));
        }

        if self.request.tls.random_sni {
            return Ok((
                Some(SniGenerator::generate_random()),
                Some(SniMethod::Random),
            ));
        }

        Ok((None, None))
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
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedWriter(self.0.clone())
        }
    }

    impl Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn initialize_with_captured_logs(scanner: &Scanner) -> (Result<()>, String) {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = tracing::subscriber::with_default(subscriber, || {
            runtime.block_on(scanner.initialize())
        });
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        (result, output)
    }

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

    fn scanner_with_family(ipv4_only: bool, ipv6_only: bool) -> Scanner {
        Scanner::new(ScanRequest {
            target: Some("example.com:443".to_string()),
            network: crate::application::scan_request::ScanRequestNetwork {
                ipv4_only,
                ipv6_only,
                ..Default::default()
            },
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

    #[tokio::test]
    async fn connectivity_probe_logs_safe_terminal_event() {
        use tracing::instrument::WithSubscriber;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose address");
        drop(listener);

        let scanner = Scanner::new(ScanRequest {
            target: Some("private.example.test:443".to_string()),
            scan: crate::application::scan_request::ScanRequestScan {
                prefs: crate::application::scan_request::ScanRequestPrefs {
                    probe_status: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("scanner should build");
        *scanner.target.write() = Target::with_ips(
            "private.example.test".to_string(),
            addr.port(),
            vec![addr.ip()],
        )
        .expect("loopback target should build");

        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(output.clone())
            .finish();
        let results = scanner
            .run_with_phases()
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await
            .expect("probe-only scan should complete");

        assert!(!results.scan_metadata.probe_status.success);
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|event| event["fields"]["event_name"] == "scan.connectivity_probe.completed")
            .expect("connectivity event should be emitted by the scan");
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["fields"]["operation"], "probe_connectivity");
        assert_eq!(event["fields"]["outcome"], "unreachable");
        assert!(event["fields"]["duration_ms"].is_number());
        assert!(event["fields"]["error_type"].is_string());
        assert!(!output.contains(&addr.ip().to_string()));
    }

    fn mixed_family_target() -> Target {
        Target::with_ips(
            "example.com".to_string(),
            443,
            vec![
                "1.2.3.4".parse().expect("v4"),
                "2606:4700::1".parse().expect("v6"),
            ],
        )
        .expect("target")
    }

    #[test]
    fn rating_with_missing_certificate_on_full_scan_zeroes_score() {
        use crate::rating::Grade;

        let scanner = Scanner::new(ScanRequest {
            target: Some("example.com:443".to_string()),
            scan: ScanRequestScan {
                scope: crate::application::scan_request::ScanRequestScope {
                    full: true,
                    ..Default::default()
                },
                prefs: crate::application::scan_request::ScanRequestPrefs {
                    probe_status: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("scanner should build");

        // Strong protocols give a high base score; no certificate_chain means
        // cert_validation is None, as when the certificate phase fails to connect.
        let make_protocol = |protocol, preferred| ProtocolTestResult {
            protocol,
            supported: true,
            inconclusive: false,
            preferred,
            ciphers_count: 8,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        };
        let results = ScanResults {
            protocols: vec![
                make_protocol(Protocol::TLS12, false),
                make_protocol(Protocol::TLS13, true),
            ],
            ..Default::default()
        };

        let rating = scanner.calculate_rating(&results);
        assert_eq!(
            rating.grade,
            Grade::Unverified,
            "a certificate phase that retrieved no certificate must be Grade Unverified (trust unknown), not T (trust failed)"
        );
        assert_eq!(
            rating.score, 0,
            "Grade Unverified must zero the overall score to avoid contradictory 'Grade Unverified (84/100)' output"
        );
    }

    #[test]
    fn address_family_filter_ipv4_only_keeps_only_ipv4() {
        let scanner = scanner_with_family(true, false);
        let filtered = scanner
            .apply_address_family_filter(mixed_family_target())
            .expect("ipv4 present");
        assert_eq!(filtered.ip_addresses.len(), 1);
        assert!(filtered.ip_addresses[0].is_ipv4());
    }

    #[test]
    fn address_family_filter_ipv6_only_keeps_only_ipv6() {
        let scanner = scanner_with_family(false, true);
        let filtered = scanner
            .apply_address_family_filter(mixed_family_target())
            .expect("ipv6 present");
        assert_eq!(filtered.ip_addresses.len(), 1);
        assert!(filtered.ip_addresses[0].is_ipv6());
    }

    #[test]
    fn address_family_filter_errors_when_family_absent() {
        let scanner = scanner_with_family(false, true);
        let only_v4 = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["1.2.3.4".parse().expect("v4")],
        )
        .expect("target");
        assert!(scanner.apply_address_family_filter(only_v4).is_err());
    }

    #[test]
    fn address_family_filter_noop_without_flags() {
        let scanner = scanner_with_family(false, false);
        let filtered = scanner
            .apply_address_family_filter(mixed_family_target())
            .expect("unfiltered");
        assert_eq!(filtered.ip_addresses.len(), 2);
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

    #[test]
    fn initialize_logs_safe_outcome_and_address_count() {
        let mut scanner = test_scanner();
        scanner.request.target = Some("private-target.test".to_string());
        scanner.request.ip = Some("8.8.8.8".to_string());

        let (result, output) = initialize_with_captured_logs(&scanner);
        result.expect("IP override initialization should succeed");
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();

        assert_eq!(event["level"], "INFO");
        assert_eq!(event["fields"]["event_name"], "scanner.target.initialized");
        assert_eq!(event["fields"]["resolution_mode"], "ip_override");
        assert_eq!(event["fields"]["resolved_address_count"], 1);
        assert_eq!(event["fields"]["outcome"], "success");
        assert!(event["fields"]["duration_ms"].is_number());
        assert!(!output.contains("private-target.test"));
        assert!(!output.contains("8.8.8.8"));
    }

    #[test]
    fn initialize_logs_safe_error_without_target_data() {
        let mut scanner = test_scanner();
        scanner.request.target = None;

        let (result, output) = initialize_with_captured_logs(&scanner);
        assert!(result.is_err());
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();

        assert_eq!(event["level"], "WARN");
        assert_eq!(
            event["fields"]["event_name"],
            "scanner.target.initialization_failed"
        );
        assert_eq!(event["fields"]["error_code"], "invalid_input");
        assert_eq!(event["fields"]["outcome"], "failed");
        assert!(event["fields"]["duration_ms"].is_number());
        assert!(!output.contains("example.com"));
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
                ip: Some("8.8.8.8".to_string()),
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
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn initialize_uses_starttls_default_port_when_target_has_no_port() {
        let scanner = Scanner::with_reporter(
            ScanRequest {
                target: Some("example.com".to_string()),
                ip: Some("8.8.8.8".to_string()),
                starttls: crate::application::scan_request::ScanRequestStarttls {
                    smtp: true,
                    ..Default::default()
                },
                scan: ScanRequestScan {
                    proto: crate::application::scan_request::ScanRequestProto {
                        enabled: true,
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

        assert_eq!(scanner.get_target_owned().port, 25);
    }

    #[tokio::test]
    async fn resolved_sni_uses_hostname_for_ip_override_scans() {
        let scanner = Scanner::with_reporter(
            ScanRequest {
                target: Some("example.com:443".to_string()),
                ip: Some("8.8.8.8".to_string()),
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
        let (_request, sni_used, method) = scanner
            .request_with_effective_sni(&target)
            .await
            .expect("effective SNI should resolve");

        assert_eq!(sni_used.as_deref(), Some("example.com"));
        assert!(matches!(method, Some(SniMethod::Hostname)));
    }
}
