// Scanner module - Main scanning engine

pub mod config;
pub mod mass;

// Multi-IP modules - Scanner is now Send-compatible, enabling parallel IP scanning
pub mod aggregation;
pub mod inconsistency;
pub mod multi_ip;

// Phase-based scan orchestration (extracted from God Method)
pub mod phases;

// Re-export domain-specific configuration objects
pub use config::{CertificateConfig, CipherTestConfig, ProtocolTestConfig};

// Re-export progress reporter types for dependency injection
pub use phases::{ScanProgressReporter, SilentProgressReporter, TerminalProgressReporter};

use crate::certificates::{
    parser::CertificateChain, revocation::RevocationResult, validator::ValidationResult,
};
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::client_sim::simulator::ClientSimulationResult;
use crate::http::tester::HeaderAnalysisResult;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::rating::{RatingCalculator, RatingResult};
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use crate::vulnerabilities::{VulnerabilityResult, merge_vulnerability_result};
use crate::{Args, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub args: Args,
    target: Arc<RwLock<Target>>,
    mtls_config: Option<MtlsConfig>,
    reporter: Arc<dyn phases::ScanProgressReporter>,
}

impl Scanner {
    /// Create a new Scanner with the default TerminalProgressReporter
    ///
    /// This is the primary constructor for CLI usage where terminal output is desired.
    /// For headless/API operation, use `with_reporter()` with a `SilentProgressReporter`.
    pub fn new(args: Args) -> Result<Self> {
        Self::with_reporter(args, Arc::new(phases::TerminalProgressReporter::new()))
    }

    /// Create a new Scanner with a custom progress reporter
    ///
    /// This constructor follows Dependency Inversion by accepting the reporter as a parameter,
    /// allowing the caller to inject different reporters for different contexts:
    /// - `TerminalProgressReporter`: CLI usage with colored terminal output
    /// - `SilentProgressReporter`: API/headless operation with no output
    /// - Custom reporters: Testing, logging, or alternative output formats
    pub fn with_reporter(
        args: Args,
        reporter: Arc<dyn phases::ScanProgressReporter>,
    ) -> Result<Self> {
        // Parse target from args
        let target_str = args
            .target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No target specified"))?;

        // Use a placeholder target with sentinel IP (0.0.0.0) since DNS resolution requires async.
        // The actual IPs are resolved in initialize() which is called by run() before any scanning.
        // The sentinel IP satisfies Target's non-empty invariant while indicating uninitialized state.
        let placeholder_ip: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        let target = Target::with_ips(
            target_str.to_string(),
            args.port.unwrap_or(443),
            vec![placeholder_ip],
        )?;

        // Load mTLS configuration if specified
        let mtls_config = if let (Some(key_path), Some(cert_path)) =
            (&args.tls.client_key, &args.tls.client_certs)
        {
            // Use separate key and certificate files
            Some(MtlsConfig::from_separate_files(
                cert_path,
                key_path,
                args.tls.client_key_password.as_deref(),
            )?)
        } else if let Some(mtls_path) = &args.tls.mtls_cert {
            // Use combined PEM file
            Some(MtlsConfig::from_pem_file(mtls_path)?)
        } else {
            None
        };

        Ok(Self {
            args,
            target: Arc::new(RwLock::new(target)),
            mtls_config,
            reporter,
        })
    }

    /// Initialize target with DNS resolution
    pub async fn initialize(&self) -> Result<()> {
        let target_str = self
            .args
            .target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No target specified"))?;

        let parsed_target = Target::parse(target_str).await?;
        *self.target.write() = parsed_target;
        Ok(())
    }

    /// Get an owned copy of the target
    fn get_target_owned(&self) -> Target {
        self.target.read().clone()
    }

    /// Set the target (used by multi-IP scanner to override target for single IP scans)
    pub fn set_target(&self, target: Target) {
        *self.target.write() = target;
    }

    /// Run complete scan using phase-based orchestration
    ///
    /// This method uses the Strategy Pattern to decompose scanning into discrete phases:
    /// - ProtocolPhase: Test SSL/TLS protocol support
    /// - CipherPhase: Enumerate cipher suites per protocol
    /// - CertificatePhase: Analyze server certificates
    /// - VulnerabilityPhase: Test known vulnerabilities
    /// - HttpHeadersPhase: Analyze HTTP security headers
    /// - FingerprintPhase: Capture TLS fingerprints (JA3, JA3S, JARM)
    /// - ClientSimPhase: Simulate client connections
    /// - SignaturePhase: Enumerate signature algorithms
    /// - GroupsPhase: Enumerate key exchange groups
    /// - ClientCasPhase: Extract client CAs list
    /// - IntolerancePhase: Test TLS intolerance
    /// - AlpnPhase: Test ALPN protocol negotiation
    ///
    /// Benefits of phase-based design:
    /// - Single Responsibility: Each phase has one clear purpose
    /// - Testability: Phases can be unit tested in isolation
    /// - Maintainability: Smaller, focused code units
    /// - Extensibility: New phases can be added without modifying existing code
    ///
    /// This is the primary implementation; `run()` delegates to this method.
    pub async fn run_with_phases(&self) -> Result<ScanResults> {
        let start_time = Instant::now();

        // Initialize target only if it still has the placeholder IP (0.0.0.0)
        // This prevents re-resolving DNS when scan_single_ip already set a specific IP
        let placeholder_ip: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        let needs_init = {
            let target = self.target.read();
            target.ip_addresses.len() == 1 && target.ip_addresses[0] == placeholder_ip
        };
        if needs_init {
            self.initialize().await?;
        }

        // Check if multi-IP scanning is enabled
        // By default, scan all IPs unless --first-ip-only is specified
        let should_run_multi_ip = {
            let target = self.target.read();
            target.ip_addresses.len() > 1 && !self.args.network.first_ip_only
        };

        if should_run_multi_ip {
            return self.run_multi_ip_scan().await;
        }

        // Create scan context with shared state
        let target = self.get_target_owned();
        let args = Arc::new(self.args.clone());
        let context = phases::ScanContext::new(target, args, self.mtls_config.clone());

        // Build phase orchestrator with all phases (12 phase classes covering 14 scan operations)
        // Use the injected reporter (follows Dependency Inversion Principle)
        let orchestrator = phases::PhaseOrchestrator::with_reporter(Arc::clone(&self.reporter))
            .add_phase(Box::new(phases::ProtocolPhase::new()))
            .add_phase(Box::new(phases::CipherPhase::new()))
            .add_phase(Box::new(phases::CertificatePhase::new()))
            .add_phase(Box::new(phases::VulnerabilityPhase::new()))
            .add_phase(Box::new(phases::HttpHeadersPhase::new()))
            .add_phase(Box::new(phases::FingerprintPhase::new()))
            .add_phase(Box::new(phases::ClientSimPhase::new()))
            .add_phase(Box::new(phases::SignaturePhase::new()))
            .add_phase(Box::new(phases::GroupsPhase::new()))
            .add_phase(Box::new(phases::ClientCasPhase::new()))
            .add_phase(Box::new(phases::IntolerancePhase::new()))
            .add_phase(Box::new(phases::AlpnPhase::new()));

        // Execute all phases in sequence
        let mut results = orchestrator.execute(context).await?;

        // Calculate overall SSL Labs rating
        if self.args.scan.all || self.args.target.is_some() {
            let rating_result = self.calculate_rating(&results);
            results.rating = Some(RatingResults {
                ssl_rating: Some(rating_result),
            });
        }

        results.scan_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(results)
    }

    /// Run complete scan and return results
    ///
    /// This method performs the scan and returns raw results without formatting.
    /// The caller is responsible for presenting the results (e.g., via ScannerFormatter).
    /// This design follows the Dependency Inversion Principle: the Scanner (domain layer)
    /// does not depend on formatters (presentation layer).
    ///
    /// Internally delegates to `run_with_phases()` which uses the Strategy Pattern
    /// to execute scanning in discrete, testable phases.
    pub async fn run(&self) -> Result<ScanResults> {
        self.run_with_phases().await
    }

    /// Calculate SSL Labs rating
    fn calculate_rating(&self, results: &ScanResults) -> RatingResult {
        let cert_validation = results.certificate_chain.as_ref().map(|c| &c.validation);

        RatingCalculator::calculate(
            &results.protocols,
            &results.ciphers,
            cert_validation,
            &results.vulnerabilities,
        )
    }

    /// Run multi-IP scan (scan all IPs in parallel)
    async fn run_multi_ip_scan(&self) -> Result<ScanResults> {
        use crate::scanner::multi_ip::MultiIpScanner;

        // Create multi-IP scanner (requires owned values)
        let scanner = MultiIpScanner::new(self.get_target_owned(), self.args.clone());

        // Execute parallel scans
        let report = scanner.scan_all_ips().await?;

        // Use conservative aggregation for multi-IP scans
        let per_ip_results: Vec<_> = report
            .per_ip_results
            .values()
            .map(|result| crate::utils::anycast::IpScanResult {
                ip: result.ip,
                results: result.scan_result.clone(),
                error: result.error.clone(),
            })
            .collect();

        let mut aggregated = self.build_conservative_multi_ip_result(&report)?;
        aggregated.scanned_ips = per_ip_results;
        // Store the full report for command layer JSON export
        aggregated.multi_ip_report = Some(report);
        Ok(aggregated)
    }

    fn build_conservative_multi_ip_result(
        &self,
        report: &crate::scanner::multi_ip::MultiIpScanReport,
    ) -> Result<ScanResults> {
        let base_scan = report
            .per_ip_results
            .values()
            .find(|result| result.is_successful())
            .ok_or_else(|| {
                crate::TlsError::Other(format!("All {} IP address scans failed", report.total_ips))
            })?;

        let mut aggregated = base_scan.scan_result.clone();

        aggregated.protocols = report.aggregated.protocols.clone();
        aggregated.ciphers = report.aggregated.ciphers.clone();
        aggregated.vulnerabilities = Self::aggregate_vulnerabilities(&report.per_ip_results);
        aggregated.certificate_chain = Self::select_common_certificate_chain(
            &report.per_ip_results,
            report.aggregated.certificate_info.as_ref(),
        );
        aggregated.inconsistencies = Some(report.inconsistencies.clone());

        let certificate_validation = aggregated
            .certificate_chain
            .as_ref()
            .map(|cert| &cert.validation);

        aggregated.rating = Some(RatingResults {
            ssl_rating: Some(RatingCalculator::calculate(
                &aggregated.protocols,
                &aggregated.ciphers,
                certificate_validation,
                &aggregated.vulnerabilities,
            )),
        });

        Ok(aggregated)
    }

    fn aggregate_vulnerabilities(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
    ) -> Vec<VulnerabilityResult> {
        let mut aggregated: Vec<VulnerabilityResult> = Vec::new();

        for result in results.values() {
            if result.error.is_some() {
                continue;
            }

            for vuln in &result.scan_result.vulnerabilities {
                let existing = aggregated
                    .iter_mut()
                    .find(|item| item.vuln_type == vuln.vuln_type);

                match existing {
                    None => aggregated.push(vuln.clone()),
                    Some(item) => merge_vulnerability_result(item, vuln),
                }
            }
        }

        aggregated
    }

    fn select_common_certificate_chain(
        results: &std::collections::HashMap<
            std::net::IpAddr,
            crate::scanner::inconsistency::SingleIpScanResult,
        >,
        certificate_info: Option<&crate::certificates::parser::CertificateInfo>,
    ) -> Option<CertificateAnalysisResult> {
        let fingerprint = certificate_info.and_then(|cert| cert.fingerprint_sha256.as_ref());
        let Some(fingerprint) = fingerprint else {
            return results
                .values()
                .filter(|result| result.error.is_none())
                .find_map(|result| result.scan_result.certificate_chain.clone());
        };

        results
            .values()
            .filter(|result| result.error.is_none())
            .find_map(|result| {
                let chain = result.scan_result.certificate_chain.as_ref()?;
                let leaf = chain.chain.leaf()?;
                if leaf.fingerprint_sha256.as_ref()? == fingerprint {
                    Some(chain.clone())
                } else {
                    None
                }
            })
    }
}

/// Certificate analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAnalysisResult {
    pub chain: CertificateChain,
    pub validation: ValidationResult,
    pub revocation: Option<RevocationResult>,
}

// =============================================================================
// Interface Segregation: Sub-structs for ScanResults
// =============================================================================

/// Fingerprint results - TLS fingerprinting data (JA3, JA3S, JARM)
///
/// Groups all fingerprinting-related fields together for Interface Segregation.
/// Consumers that only need fingerprint data can work with this struct directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintResults {
    pub ja3_fingerprint: Option<crate::fingerprint::Ja3Fingerprint>,
    pub ja3_match: Option<crate::fingerprint::Ja3Signature>,
    pub ja3s_fingerprint: Option<crate::fingerprint::Ja3sFingerprint>,
    pub ja3s_match: Option<crate::fingerprint::Ja3sSignature>,
    pub jarm_fingerprint: Option<crate::fingerprint::JarmFingerprint>,
    pub client_hello_raw: Option<Vec<u8>>,
    pub server_hello_raw: Option<Vec<u8>>,
}

/// HTTP results - HTTP header analysis data
///
/// Groups HTTP-related fields for Interface Segregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResults {
    pub http_headers: Option<HeaderAnalysisResult>,
}

/// Rating results - SSL Labs rating data
///
/// Groups rating-related fields for Interface Segregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RatingResults {
    pub ssl_rating: Option<RatingResult>,
}

/// Advanced results - Optional advanced analysis data
///
/// Groups optional/advanced fields for Interface Segregation.
/// These are typically only populated when specific flags are used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvancedResults {
    pub intolerance: Option<crate::protocols::intolerance::IntoleranceTestResult>,
    pub alpn_result: Option<crate::protocols::alpn::AlpnReport>,
    pub signature_algorithms: Option<crate::protocols::signatures::SignatureEnumerationResult>,
    pub key_exchange_groups: Option<crate::protocols::groups::GroupEnumerationResult>,
    pub client_simulations: Option<Vec<ClientSimulationResult>>,
    pub client_cas: Option<crate::protocols::client_cas::ClientCAsResult>,
    pub cdn_detection: Option<crate::fingerprint::CdnDetection>,
    pub load_balancer_info: Option<crate::fingerprint::LoadBalancerInfo>,
    /// CT log source (if certificate discovered via CT logs)
    pub ct_log_source: Option<String>,
    /// CT log index (if certificate discovered via CT logs)
    pub ct_log_index: Option<u64>,
}

/// Scan results - Main struct with ISP-compliant composition
///
/// Uses composition of sub-structs for Interface Segregation Principle compliance.
/// Consumers can access only the data they need through the appropriate sub-struct.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResults {
    // Core results (always present)
    pub target: String,
    pub scan_time_ms: u64,

    // Protocol & Cipher results
    pub protocols: Vec<ProtocolTestResult>,
    pub ciphers: HashMap<Protocol, ProtocolCipherSummary>,

    // Certificate results (optional group)
    pub certificate_chain: Option<CertificateAnalysisResult>,

    // Fingerprint results (optional group)
    pub fingerprints: Option<FingerprintResults>,

    // HTTP results (optional group)
    pub http: Option<HttpResults>,

    // Vulnerability results
    pub vulnerabilities: Vec<VulnerabilityResult>,

    // Rating
    pub rating: Option<RatingResults>,

    // Advanced/Optional results
    pub advanced: Option<AdvancedResults>,

    // Multi-IP scan metadata
    pub pre_handshake_used: bool,
    pub scanned_ips: Vec<crate::utils::anycast::IpScanResult>,
    pub sni_used: Option<String>,
    pub sni_generation_method: Option<SniMethod>,
    pub probe_status: crate::output::probe_status::ProbeStatus,
    pub inconsistencies: Option<Vec<crate::scanner::inconsistency::Inconsistency>>,

    /// Full multi-IP scan report (only populated for multi-IP scans)
    /// This is used by the command layer for JSON export of per-IP results.
    #[serde(skip)]
    pub multi_ip_report: Option<crate::scanner::multi_ip::MultiIpScanReport>,
}

// =============================================================================
// Convenience accessor methods for backward compatibility
// =============================================================================

impl ScanResults {
    /// Get HTTP headers (convenience accessor)
    pub fn http_headers(&self) -> Option<&HeaderAnalysisResult> {
        self.http.as_ref().and_then(|h| h.http_headers.as_ref())
    }

    /// Get SSL rating (convenience accessor)
    pub fn ssl_rating(&self) -> Option<&RatingResult> {
        self.rating.as_ref().and_then(|r| r.ssl_rating.as_ref())
    }

    /// Get JA3 fingerprint (convenience accessor)
    pub fn ja3_fingerprint(&self) -> Option<&crate::fingerprint::Ja3Fingerprint> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3_fingerprint.as_ref())
    }

    /// Get JA3 match (convenience accessor)
    pub fn ja3_match(&self) -> Option<&crate::fingerprint::Ja3Signature> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3_match.as_ref())
    }

    /// Get JA3S fingerprint (convenience accessor)
    pub fn ja3s_fingerprint(&self) -> Option<&crate::fingerprint::Ja3sFingerprint> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3s_fingerprint.as_ref())
    }

    /// Get JA3S match (convenience accessor)
    pub fn ja3s_match(&self) -> Option<&crate::fingerprint::Ja3sSignature> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3s_match.as_ref())
    }

    /// Get JARM fingerprint (convenience accessor)
    pub fn jarm_fingerprint(&self) -> Option<&crate::fingerprint::JarmFingerprint> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.jarm_fingerprint.as_ref())
    }

    /// Get client simulations (convenience accessor)
    pub fn client_simulations(&self) -> Option<&Vec<ClientSimulationResult>> {
        self.advanced
            .as_ref()
            .and_then(|a| a.client_simulations.as_ref())
    }

    /// Get intolerance results (convenience accessor)
    pub fn intolerance(&self) -> Option<&crate::protocols::intolerance::IntoleranceTestResult> {
        self.advanced.as_ref().and_then(|a| a.intolerance.as_ref())
    }

    /// Get ALPN result (convenience accessor)
    pub fn alpn_result(&self) -> Option<&crate::protocols::alpn::AlpnReport> {
        self.advanced.as_ref().and_then(|a| a.alpn_result.as_ref())
    }

    /// Get signature algorithms (convenience accessor)
    pub fn signature_algorithms(
        &self,
    ) -> Option<&crate::protocols::signatures::SignatureEnumerationResult> {
        self.advanced
            .as_ref()
            .and_then(|a| a.signature_algorithms.as_ref())
    }

    /// Get key exchange groups (convenience accessor)
    pub fn key_exchange_groups(&self) -> Option<&crate::protocols::groups::GroupEnumerationResult> {
        self.advanced
            .as_ref()
            .and_then(|a| a.key_exchange_groups.as_ref())
    }

    /// Get client CAs (convenience accessor)
    pub fn client_cas(&self) -> Option<&crate::protocols::client_cas::ClientCAsResult> {
        self.advanced.as_ref().and_then(|a| a.client_cas.as_ref())
    }

    /// Get CDN detection (convenience accessor)
    pub fn cdn_detection(&self) -> Option<&crate::fingerprint::CdnDetection> {
        self.advanced
            .as_ref()
            .and_then(|a| a.cdn_detection.as_ref())
    }

    /// Get load balancer info (convenience accessor)
    pub fn load_balancer_info(&self) -> Option<&crate::fingerprint::LoadBalancerInfo> {
        self.advanced
            .as_ref()
            .and_then(|a| a.load_balancer_info.as_ref())
    }

    /// Ensure fingerprints sub-struct exists and return mutable reference
    pub fn fingerprints_mut(&mut self) -> &mut FingerprintResults {
        self.fingerprints
            .get_or_insert_with(FingerprintResults::default)
    }

    /// Ensure http sub-struct exists and return mutable reference
    pub fn http_mut(&mut self) -> &mut HttpResults {
        self.http.get_or_insert_with(HttpResults::default)
    }

    /// Ensure rating sub-struct exists and return mutable reference
    pub fn rating_mut(&mut self) -> &mut RatingResults {
        self.rating.get_or_insert_with(RatingResults::default)
    }

    /// Ensure advanced sub-struct exists and return mutable reference
    pub fn advanced_mut(&mut self) -> &mut AdvancedResults {
        self.advanced.get_or_insert_with(AdvancedResults::default)
    }
}

/// SNI generation method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SniMethod {
    Hostname,
    ReversePTR,
    Random,
    Custom(String),
}

impl ScanResults {
    /// Export to JSON
    pub fn to_json(&self, pretty: bool) -> Result<String> {
        if pretty {
            Ok(serde_json::to_string_pretty(self)?)
        } else {
            Ok(serde_json::to_string(self)?)
        }
    }

    /// Export to CSV (simplified)
    pub fn to_csv(&self) -> Result<String> {
        let mut csv = String::new();

        // Vulnerabilities CSV
        csv.push_str("Type,Severity,Vulnerable,CVE,Details\n");
        for vuln in &self.vulnerabilities {
            csv.push_str(&format!(
                "{:?},{:?},{},{},{}\n",
                vuln.vuln_type,
                vuln.severity,
                vuln.vulnerable,
                vuln.cve.as_deref().unwrap_or("N/A"),
                vuln.details.replace(',', ";")
            ));
        }

        Ok(csv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_results_json() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1234,
            ..Default::default()
        };

        let json = results
            .to_json(false)
            .expect("test assertion should succeed");
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_scan_results_csv() {
        let results = ScanResults::default();
        let csv = results.to_csv().expect("test assertion should succeed");
        assert!(csv.contains("Type,Severity"));
    }
}
