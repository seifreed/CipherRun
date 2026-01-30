// ALPN Protocol Negotiation Phase - Tests Application-Layer Protocol Negotiation
//
// This phase tests ALPN (Application-Layer Protocol Negotiation) support,
// a TLS extension that allows the client and server to negotiate which
// application-layer protocol to use over the secure connection (e.g., HTTP/2,
// HTTP/3, SPDY, gRPC).
//
// Responsibilities (Single Responsibility Principle):
// - Configure ALPN tester
// - Execute ALPN negotiation tests
// - Store ALPN test results in scan context
//
// Dependencies:
// - AlpnTester (domain logic for ALPN testing)
// - Args (CLI configuration)
// - Target (server information)
//
// ALPN protocols tested:
// - HTTP/2 (h2)
// - HTTP/1.1 (http/1.1)
// - HTTP/3 (h3)
// - SPDY variants (spdy/3.1, spdy/3)
// - gRPC (grpc-exp)
// - WebRTC (webrtc)

use super::{ScanContext, ScanPhase};
use crate::protocols::alpn::AlpnTester;
use crate::{Args, Result};
use async_trait::async_trait;

/// ALPN protocol negotiation phase
///
/// Tests which application-layer protocols the target server supports
/// via the ALPN TLS extension. ALPN allows efficient protocol negotiation
/// without additional round trips, commonly used for HTTP/2 and HTTP/3.
///
/// Configuration sources (from Args):
/// - Full scan mode (--all) enables ALPN testing
/// - Target information (hostname, port, resolved IPs)
pub struct AlpnPhase;

impl AlpnPhase {
    /// Create a new ALPN protocol negotiation phase
    pub fn new() -> Self {
        Self
    }
}

impl Default for AlpnPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for AlpnPhase {
    fn name(&self) -> &'static str {
        "Testing ALPN Protocol Negotiation"
    }

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Full scan mode (--all)
        args.scan.all
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create ALPN tester with target
        let tester = AlpnTester::new(context.target());

        // Get comprehensive ALPN report
        // This tests:
        // 1. Support for HTTP/2 (h2)
        // 2. Support for HTTP/1.1 (http/1.1)
        // 3. Support for HTTP/3 (h3)
        // 4. Support for SPDY protocols
        // 5. Support for gRPC
        // 6. Protocol preference order
        let alpn_results = tester.get_comprehensive_report().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.advanced_mut().alpn_result = Some(alpn_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_phase_should_run() {
        let phase = AlpnPhase::new();

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
    fn test_alpn_phase_name() {
        let phase = AlpnPhase::new();
        assert_eq!(phase.name(), "Testing ALPN Protocol Negotiation");
    }
}
