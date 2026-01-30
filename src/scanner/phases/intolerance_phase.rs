// TLS Intolerance Testing Phase - Tests for TLS version intolerance
//
// This phase tests whether the target server exhibits TLS version intolerance,
// a compatibility issue where servers incorrectly reject TLS handshakes with
// newer protocol versions in the ClientHello, even when falling back to an
// older supported version. This was common with TLS 1.3 deployment.
//
// Responsibilities (Single Responsibility Principle):
// - Configure intolerance tester
// - Execute TLS intolerance tests
// - Store intolerance test results in scan context
//
// Dependencies:
// - IntoleranceTester (domain logic for intolerance testing)
// - Args (CLI configuration)
// - Target (server information)
//
// Intolerance types tested:
// - TLS 1.3 intolerance (rejects ClientHello with TLS 1.3)
// - TLS 1.2 intolerance (rejects ClientHello with TLS 1.2)
// - TLS 1.1 intolerance (rejects ClientHello with TLS 1.1)
// - Extension intolerance (rejects specific TLS extensions)
// - Cipher suite intolerance (rejects large cipher lists)

use super::{ScanContext, ScanPhase};
use crate::protocols::intolerance::IntoleranceTester;
use crate::{Args, Result};
use async_trait::async_trait;

/// TLS intolerance testing phase
///
/// Tests whether the target server exhibits version intolerance or
/// other TLS handshake intolerance issues. Intolerant servers incorrectly
/// reject valid TLS handshakes, causing compatibility problems with modern
/// clients.
///
/// Configuration sources (from Args):
/// - Full scan mode (--all) enables intolerance testing
/// - Target information (hostname, port, resolved IPs)
pub struct IntolerancePhase;

impl IntolerancePhase {
    /// Create a new TLS intolerance testing phase
    pub fn new() -> Self {
        Self
    }
}

impl Default for IntolerancePhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for IntolerancePhase {
    fn name(&self) -> &'static str {
        "Testing TLS Intolerance"
    }

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Full scan mode (--all)
        args.scan.all
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create intolerance tester with target
        let tester = IntoleranceTester::new(context.target());

        // Test all intolerance scenarios
        // This tests:
        // 1. Version intolerance (TLS 1.3, 1.2, 1.1)
        // 2. Extension intolerance (rejects specific extensions)
        // 3. Cipher suite intolerance (rejects large cipher lists)
        // 4. Record size intolerance (rejects large handshake records)
        let intolerance_results = tester.test_all().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.advanced_mut().intolerance = Some(intolerance_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intolerance_phase_should_run() {
        let phase = IntolerancePhase::new();

        // Test with --all flag
        let mut args = Args::default();
        args.scan.all = true;
        assert!(phase.should_run(&args));

        // Test without --all flag
        let args = Args::default();
        assert!(!phase.should_run(&args));

        // Test with target but no --all
        let mut args = Args::default();
        args.target = Some("example.com".to_string());
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_intolerance_phase_name() {
        let phase = IntolerancePhase::new();
        assert_eq!(phase.name(), "Testing TLS Intolerance");
    }
}
