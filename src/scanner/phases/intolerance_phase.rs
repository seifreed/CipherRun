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
// - ScanRequest (scan configuration)
// - Target (server information)
//
// Intolerance types tested:
// - TLS 1.3 intolerance (rejects ClientHello with TLS 1.3)
// - TLS 1.2 intolerance (rejects ClientHello with TLS 1.2)
// - TLS 1.1 intolerance (rejects ClientHello with TLS 1.1)
// - Extension intolerance (rejects specific TLS extensions)
// - Cipher suite intolerance (rejects large cipher lists)

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use crate::protocols::intolerance::IntoleranceTester;
use async_trait::async_trait;

/// TLS intolerance testing phase
///
/// Tests whether the target server exhibits version intolerance or
/// other TLS handshake intolerance issues. Intolerant servers incorrectly
/// reject valid TLS handshakes, causing compatibility problems with modern
/// clients.
///
/// Configuration sources (from ScanRequest):
/// - Baseline scan policy enables intolerance testing
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

    fn should_run(&self, args: &ScanRequest) -> bool {
        // Run if:
        // - Baseline scan policy enables intolerance testing
        args.should_run_intolerance_phase()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create intolerance tester with target
        let tester =
            IntoleranceTester::new(context.target()).with_sni(context.args.tls.sni_name.clone());

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
    use crate::scanner::phases::test_scan_context;

    #[test]
    fn test_intolerance_phase_should_run() {
        let phase = IntolerancePhase::new();

        // Test with baseline
        let mut args = ScanRequest::default();
        args.scan.scope.all = true;
        assert!(phase.should_run(&args));

        // Specific-focus scans should not implicitly enable intolerance testing.
        let mut args = ScanRequest::default();
        args.scan.scope.all = true;
        args.scan.ciphers.show_sigs = true;
        assert!(!phase.should_run(&args));

        // Test without --all flag
        let args = ScanRequest::default();
        assert!(!phase.should_run(&args));

        // Test with target but no --all
        let args = ScanRequest {
            target: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_intolerance_phase_name() {
        let phase = IntolerancePhase::new();
        assert_eq!(phase.name(), "Testing TLS Intolerance");
    }

    #[test]
    fn test_intolerance_phase_default() {
        assert_eq!(IntolerancePhase.name(), "Testing TLS Intolerance");
    }

    #[tokio::test]
    async fn test_execute_stores_results_for_unreachable_target() {
        let mut context = test_scan_context(ScanRequest::default());
        context.target = crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            9,
            vec!["127.0.0.1".parse().expect("valid loopback address")],
        )
        .expect("loopback target should build");

        IntolerancePhase::new()
            .execute(&mut context)
            .await
            .expect("failed TLS probes should yield an inconclusive result");

        assert!(
            context
                .results
                .advanced
                .as_ref()
                .and_then(|results| results.intolerance.as_ref())
                .is_some()
        );
    }
}
