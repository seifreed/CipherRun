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
// - ScanRequest (scan configuration)
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
use crate::Result;
use crate::application::ScanRequest;
use crate::protocols::alpn::AlpnTester;
use async_trait::async_trait;

/// ALPN protocol negotiation phase
///
/// Tests which application-layer protocols the target server supports
/// via the ALPN TLS extension. ALPN allows efficient protocol negotiation
/// without additional round trips, commonly used for HTTP/2 and HTTP/3.
///
/// Configuration sources (from ScanRequest):
/// - Baseline scan policy enables ALPN testing
/// - Target information (hostname, port, resolved IPs)
#[derive(Default)]
pub struct AlpnPhase;

impl AlpnPhase {
    /// Create a new ALPN protocol negotiation phase
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanPhase for AlpnPhase {
    fn name(&self) -> &'static str {
        "Testing ALPN Protocol Negotiation"
    }

    fn should_run(&self, args: &ScanRequest) -> bool {
        // Run if:
        // - Baseline scan policy enables ALPN testing
        args.should_run_alpn_phase()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create ALPN tester with target
        let tester = AlpnTester::new(context.target())
            .with_starttls(
                context.args.starttls_protocol(),
                context.args.starttls.xmpphost.clone(),
            )
            .with_starttls_server_mode(context.args.starttls_server_mode())
            .with_test_all_ips(context.args.network.test_all_ips);

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
    use crate::scanner::phases::test_scan_context;

    #[test]
    fn test_alpn_phase_should_run() {
        let phase = AlpnPhase::new();

        // Test with baseline
        let mut args = ScanRequest::default();
        args.scan.scope.all = true;
        assert!(phase.should_run(&args));

        // Specific-focus scans should not implicitly enable ALPN testing.
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
    fn test_alpn_phase_name() {
        let phase = AlpnPhase::new();
        assert_eq!(phase.name(), "Testing ALPN Protocol Negotiation");
    }

    #[tokio::test]
    async fn test_execute_stores_alpn_results_for_inactive_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let mut context = test_scan_context(ScanRequest::default());
        context.target = crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid loopback address")],
        )
        .expect("loopback target should build");

        AlpnPhase::new()
            .execute(&mut context)
            .await
            .expect("failed ALPN probes should produce an inconclusive result");

        assert!(
            context
                .results
                .advanced
                .as_ref()
                .and_then(|results| results.alpn_result.as_ref())
                .is_some()
        );
    }
}
