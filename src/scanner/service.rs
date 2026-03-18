use super::{RatingResults, ScanResults, builders, phases};
use crate::Result;
use crate::application::ScanRequest;
use crate::rating::{RatingCalculator, RatingResult};
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Instant;

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
        let target_str = request
            .target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No target specified"))?;

        // Use a placeholder target with sentinel IP (0.0.0.0) since DNS resolution requires async.
        // The actual IPs are resolved in initialize() which is called by run() before any scanning.
        let placeholder_ip: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        let target = Target::with_ips(
            target_str.to_string(),
            request.port.unwrap_or(443),
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
        let target_str = self
            .request
            .target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No target specified"))?;

        let parsed_target = Target::parse(target_str).await?;
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
        let start_time = Instant::now();

        let placeholder_ip: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        let needs_init = {
            let target = self.target.read();
            target.ip_addresses.len() == 1 && target.ip_addresses[0] == placeholder_ip
        };
        if needs_init {
            self.initialize().await?;
        }

        let should_run_multi_ip = {
            let target = self.target.read();
            target.ip_addresses.len() > 1 && !self.request.network.first_ip_only
        };

        if should_run_multi_ip {
            return self.run_multi_ip_scan().await;
        }

        let context = builders::build_scan_context(
            self.get_target_owned(),
            self.request.clone(),
            self.mtls_config.clone(),
        );
        let orchestrator = builders::build_phase_orchestrator(self.reporter.clone());

        let mut results = orchestrator.execute(context).await?;

        if self.request.scan.all || self.request.has_target() {
            let rating_result = self.calculate_rating(&results);
            results.rating = Some(RatingResults {
                ssl_rating: Some(rating_result),
            });
        }

        results.scan_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(results)
    }

    /// Run complete scan and return results
    pub async fn run(&self) -> Result<ScanResults> {
        self.run_with_phases().await
    }

    fn calculate_rating(&self, results: &ScanResults) -> RatingResult {
        let cert_validation = results.certificate_chain.as_ref().map(|c| &c.validation);

        RatingCalculator::calculate(
            &results.protocols,
            &results.ciphers,
            cert_validation,
            &results.vulnerabilities,
        )
    }
}
