// Scanner Phase System - Modular scan orchestration
//
// This module implements the Strategy Pattern to decompose the Scanner's monolithic
// run() method into discrete, testable phases. Each phase encapsulates a specific
// scanning responsibility (protocols, ciphers, certificates, vulnerabilities).
//
// Benefits:
// - Single Responsibility Principle: Each phase has one clear purpose
// - Open/Closed Principle: New phases can be added without modifying existing code
// - Dependency Inversion: Scanner depends on ScanPhase abstraction, not concrete phases
// - Testability: Phases can be tested in isolation
// - Maintainability: Phases are smaller, focused units (~50-100 lines each)

pub mod alpn_phase;
pub mod certificate_phase;
pub mod cipher_phase;
pub mod client_cas_phase;
pub mod client_sim_phase;
pub mod fingerprint_phase;
pub mod groups_phase;
pub mod http_headers_phase;
pub mod intolerance_phase;
pub mod protocol_phase;
pub mod signature_phase;
pub mod vulnerability_phase;

pub use alpn_phase::AlpnPhase;
pub use certificate_phase::CertificatePhase;
pub use cipher_phase::CipherPhase;
pub use client_cas_phase::ClientCasPhase;
pub use client_sim_phase::ClientSimPhase;
pub use fingerprint_phase::FingerprintPhase;
pub use groups_phase::GroupsPhase;
pub use http_headers_phase::HttpHeadersPhase;
pub use intolerance_phase::IntolerancePhase;
pub use protocol_phase::ProtocolPhase;
pub use signature_phase::SignaturePhase;
pub use vulnerability_phase::VulnerabilityPhase;

use crate::scanner::ScanResults;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use crate::{Args, Result};
use async_trait::async_trait;
use std::sync::Arc;

// =============================================================================
// Progress Reporting Trait
// =============================================================================

/// Trait for reporting scan progress
///
/// This trait decouples progress reporting from domain logic, enabling:
/// - Terminal output for CLI usage
/// - Silent operation for API/headless mode
/// - Custom reporters for integration testing
pub trait ScanProgressReporter: Send + Sync {
    /// Called when a phase starts execution
    fn on_phase_start(&self, phase_name: &str);

    /// Called when a phase completes successfully
    fn on_phase_complete(&self, phase_name: &str);
}

/// Terminal progress reporter with colored output
///
/// Uses colored crate to display phase names in yellow/bold.
/// This is the default reporter for CLI operation.
pub struct TerminalProgressReporter;

impl TerminalProgressReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanProgressReporter for TerminalProgressReporter {
    fn on_phase_start(&self, phase_name: &str) {
        use colored::*;
        println!("\n{}", format!("{}...", phase_name).yellow().bold());
    }

    fn on_phase_complete(&self, _phase_name: &str) {
        // Terminal reporter doesn't print completion message
        // The next phase start or scan completion provides feedback
    }
}

/// Silent progress reporter for headless/API operation
///
/// Produces no output, suitable for:
/// - API server operation
/// - Batch processing
/// - Integration testing
pub struct SilentProgressReporter;

impl SilentProgressReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SilentProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanProgressReporter for SilentProgressReporter {
    fn on_phase_start(&self, _phase_name: &str) {
        // Intentionally empty - silent operation
    }

    fn on_phase_complete(&self, _phase_name: &str) {
        // Intentionally empty - silent operation
    }
}

/// Phase execution trait for the Strategy Pattern
///
/// Each scan phase implements this trait to provide:
/// - name(): Human-readable phase identifier for logging
/// - should_run(): Conditional execution based on CLI arguments
/// - execute(): Core phase logic with access to shared context
///
/// Design: async_trait is required for async methods in traits (Rust limitation)
#[async_trait]
pub trait ScanPhase: Send + Sync {
    /// Phase name for logging and debugging
    fn name(&self) -> &'static str;

    /// Determine if this phase should execute based on CLI arguments
    ///
    /// This method implements the Strategy Pattern's selection logic.
    /// Phases can be conditionally enabled based on flags like:
    /// - --protocols, --all, --vulnerabilities
    /// - Presence of target (default scan)
    fn should_run(&self, args: &Args) -> bool;

    /// Execute the phase and update the scan context
    ///
    /// This is the core Strategy Pattern method. Each phase:
    /// 1. Reads configuration from context.args
    /// 2. Performs its specific scanning task
    /// 3. Updates context.results with findings
    /// 4. Returns Result for error propagation
    async fn execute(&self, context: &mut ScanContext) -> Result<()>;
}

/// Shared scan context for phase orchestration
///
/// This struct implements the Context object in the Strategy Pattern.
/// It provides:
/// - Immutable shared state (target, args, config)
/// - Mutable result accumulation (results)
/// - Clean separation between configuration and results
///
/// Design decisions:
/// - Arc<Args> for zero-copy sharing across phases
/// - Owned Target for phase-specific modifications (e.g., IP override)
/// - Owned ScanResults for incremental accumulation
/// - Optional MtlsConfig for mTLS-enabled connections
pub struct ScanContext {
    /// Target server information (hostname, port, resolved IPs)
    pub target: Target,

    /// Accumulated scan results (modified by each phase)
    pub results: ScanResults,

    /// CLI arguments (immutable, shared across phases)
    pub args: Arc<Args>,

    /// Optional mTLS configuration for client authentication
    pub mtls_config: Option<MtlsConfig>,
}

impl ScanContext {
    /// Create a new scan context
    ///
    /// # Arguments
    /// * `target` - Target server to scan
    /// * `args` - CLI arguments wrapped in Arc for efficient sharing
    /// * `mtls_config` - Optional reference to mTLS configuration
    pub fn new(target: Target, args: Arc<Args>, mtls_config: Option<MtlsConfig>) -> Self {
        let target_str = format!("{}:{}", target.hostname, target.port);

        Self {
            target,
            results: ScanResults {
                target: target_str,
                scan_time_ms: 0,
                ..Default::default()
            },
            args,
            mtls_config,
        }
    }

    /// Get a clone of the target (for phase-specific usage)
    ///
    /// Design: Clone instead of reference to allow phases to modify
    /// their local target without affecting other phases
    pub fn target(&self) -> Target {
        self.target.clone()
    }
}

/// Phase orchestrator for executing scan phases in sequence
///
/// This struct implements the orchestration layer of the Strategy Pattern.
/// It manages phase lifecycle:
/// 1. Phase registration
/// 2. Conditional execution (should_run checks)
/// 3. Error handling and propagation
/// 4. Progress tracking via injectable reporter
pub struct PhaseOrchestrator {
    phases: Vec<Box<dyn ScanPhase>>,
    reporter: Option<Arc<dyn ScanProgressReporter>>,
}

impl PhaseOrchestrator {
    /// Create a new orchestrator with no phases
    pub fn new() -> Self {
        Self {
            phases: Vec::new(),
            reporter: None,
        }
    }

    /// Create a new orchestrator with a progress reporter
    pub fn with_reporter(reporter: Arc<dyn ScanProgressReporter>) -> Self {
        Self {
            phases: Vec::new(),
            reporter: Some(reporter),
        }
    }

    /// Set the progress reporter
    pub fn set_reporter(mut self, reporter: Arc<dyn ScanProgressReporter>) -> Self {
        self.reporter = Some(reporter);
        self
    }

    /// Register a phase for execution
    ///
    /// Phases execute in registration order, so order matters:
    /// 1. ProtocolPhase (determines supported protocols)
    /// 2. CipherPhase (tests ciphers for supported protocols)
    /// 3. CertificatePhase (analyzes server certificates)
    /// 4. VulnerabilityPhase (tests known vulnerabilities)
    /// 5. HttpHeadersPhase (analyzes HTTP security headers)
    /// 6. FingerprintPhase (captures TLS fingerprints: JA3, JA3S, JARM)
    pub fn add_phase(mut self, phase: Box<dyn ScanPhase>) -> Self {
        self.phases.push(phase);
        self
    }

    /// Execute all registered phases in sequence
    ///
    /// For each phase:
    /// 1. Check if it should run (conditional execution)
    /// 2. Report phase start via reporter (if configured)
    /// 3. Execute phase logic
    /// 4. Report phase completion via reporter (if configured)
    /// 5. Propagate errors immediately (fail-fast)
    ///
    /// Returns the final accumulated scan results
    pub async fn execute(&self, mut context: ScanContext) -> Result<ScanResults> {
        for phase in &self.phases {
            if phase.should_run(&context.args) {
                if let Some(ref reporter) = self.reporter {
                    reporter.on_phase_start(phase.name());
                }

                phase.execute(&mut context).await?;

                if let Some(ref reporter) = self.reporter {
                    reporter.on_phase_complete(phase.name());
                }
            }
        }

        Ok(context.results)
    }
}

impl Default for PhaseOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test reporter that counts calls
    struct CountingReporter {
        start_count: AtomicUsize,
        complete_count: AtomicUsize,
    }

    impl CountingReporter {
        fn new() -> Self {
            Self {
                start_count: AtomicUsize::new(0),
                complete_count: AtomicUsize::new(0),
            }
        }

        fn start_count(&self) -> usize {
            self.start_count.load(Ordering::SeqCst)
        }

        fn complete_count(&self) -> usize {
            self.complete_count.load(Ordering::SeqCst)
        }
    }

    impl ScanProgressReporter for CountingReporter {
        fn on_phase_start(&self, _phase_name: &str) {
            self.start_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_phase_complete(&self, _phase_name: &str) {
            self.complete_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_terminal_reporter_creation() {
        let reporter = TerminalProgressReporter::new();
        // Just verify it can be created without panicking
        reporter.on_phase_start("Test Phase");
        reporter.on_phase_complete("Test Phase");
    }

    #[test]
    fn test_silent_reporter_creation() {
        let reporter = SilentProgressReporter::new();
        // Just verify it can be created without panicking
        reporter.on_phase_start("Test Phase");
        reporter.on_phase_complete("Test Phase");
    }

    #[test]
    fn test_counting_reporter() {
        let reporter = CountingReporter::new();
        assert_eq!(reporter.start_count(), 0);
        assert_eq!(reporter.complete_count(), 0);

        reporter.on_phase_start("Phase 1");
        assert_eq!(reporter.start_count(), 1);

        reporter.on_phase_complete("Phase 1");
        assert_eq!(reporter.complete_count(), 1);

        reporter.on_phase_start("Phase 2");
        reporter.on_phase_complete("Phase 2");
        assert_eq!(reporter.start_count(), 2);
        assert_eq!(reporter.complete_count(), 2);
    }

    #[test]
    fn test_orchestrator_with_reporter() {
        let reporter = Arc::new(CountingReporter::new());
        let orchestrator = PhaseOrchestrator::with_reporter(reporter.clone());
        assert!(orchestrator.reporter.is_some());
    }

    #[test]
    fn test_orchestrator_set_reporter() {
        let reporter = Arc::new(SilentProgressReporter::new());
        let orchestrator = PhaseOrchestrator::new().set_reporter(reporter);
        assert!(orchestrator.reporter.is_some());
    }

    #[test]
    fn test_orchestrator_default_no_reporter() {
        let orchestrator = PhaseOrchestrator::new();
        assert!(orchestrator.reporter.is_none());
    }
}
