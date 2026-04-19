// Protocol Testing Phase - Tests SSL/TLS protocol support
//
// This phase is responsible for determining which SSL/TLS protocols
// the target server supports (SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3).
//
// Responsibilities (Single Responsibility Principle):
// - Configure protocol tester with CLI arguments
// - Execute protocol enumeration
// - Store results in scan context
//
// Dependencies:
// - ProtocolTester (domain logic for protocol testing)
// - ScanRequest (scan configuration)
// - Target (server information)

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use crate::protocols::tester::ProtocolTester;
use async_trait::async_trait;

/// Protocol testing phase
///
/// Tests which SSL/TLS protocol versions are supported by the target server.
/// This phase must execute before CipherPhase since cipher testing requires
/// knowing which protocols are available.
///
/// Configuration sources (from ScanRequest):
/// - STARTTLS protocol selection (--starttls-smtp, --starttls-imap, etc.)
/// - Protocol filters (--ssl2, --ssl3, --tls10, --tls11, --tls12, --tls13)
/// - SNI hostname override (--sni-name)
/// - Bug workarounds (--bugs)
/// - RDP mode (--rdp)
/// - Multi-IP testing (--test-all-ips)
/// - mTLS client authentication (--mtls, --pk, --certs)
pub struct ProtocolPhase;

impl ProtocolPhase {
    /// Create a new protocol testing phase
    pub fn new() -> Self {
        Self
    }

    /// Configure ProtocolTester with CLI arguments
    ///
    /// This method implements the Builder Pattern to construct a properly
    /// configured ProtocolTester based on CLI flags. It centralizes all
    /// protocol testing configuration logic in one place.
    ///
    /// Configuration applied:
    /// - mTLS: Client certificate authentication if --mtls specified
    /// - STARTTLS: Protocol-specific handshake negotiation
    /// - RDP: Special RDP-specific TLS handling
    /// - Bugs mode: OpenSSL bug workarounds for broken servers
    /// - SNI: Custom Server Name Indication
    /// - Protocol filter: Test only specific protocols
    /// - Multi-IP: Test all resolved IP addresses
    fn configure_tester(&self, context: &ScanContext) -> ProtocolTester {
        let target = context.target();
        let adaptive = context.adaptive.clone();

        // Base tester with optional mTLS
        let mut tester = if let Some(ref mtls_config) = context.mtls_config {
            ProtocolTester::with_mtls(target.clone(), mtls_config.clone())
        } else {
            ProtocolTester::new(target.clone())
        };

        // Apply adaptive timeouts and retry configuration
        tester = tester
            .with_connect_timeout(adaptive.connect_timeout())
            .with_read_timeout(adaptive.socket_timeout());
        if let Some(retry_config) = context.args.retry_config() {
            tester = tester.with_retry_config(Some(retry_config.with_adaptive(adaptive.clone())));
        }

        // Enable RDP mode if specified
        if context.args.starttls.rdp {
            tester = tester.with_rdp(true);
        }

        // Enable bug workarounds if specified
        // This helps scan servers with broken TLS implementations
        if context.args.tls.bugs {
            tester = tester.with_bugs_mode(true);
        }

        // Enable STARTTLS if specified
        // Examples: SMTP, IMAP, POP3, FTP, LDAP, XMPP
        if let Some(starttls_proto) = context.args.starttls_protocol() {
            tester = tester.with_starttls(Some(starttls_proto));
            tester = tester.with_starttls_hostname(context.args.starttls.xmpphost.clone());
        }

        // Set custom SNI if specified
        // Useful for CDN/vhost testing where SNI affects certificate selection
        if let Some(ref sni) = context.args.tls.sni_name {
            tester = tester.with_sni(Some(sni.clone()));
        }

        // Set protocol filter if specified
        // Allows testing only specific protocols (e.g., --tls12 --tls13)
        if let Some(protocols) = context.args.protocols_to_test() {
            tester = tester.with_protocol_filter(Some(protocols));
        }

        // Enable testing all IPs if specified
        // Useful for load balancer/Anycast detection
        if context.args.network.test_all_ips {
            tester = tester.with_test_all_ips(true);
        }

        tester
    }
}

impl Default for ProtocolPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for ProtocolPhase {
    fn name(&self) -> &'static str {
        "Testing SSL/TLS Protocols"
    }

    fn should_run(&self, args: &ScanRequest) -> bool {
        args.should_run_protocol_phase()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Configure tester with all CLI options
        let tester = self.configure_tester(context);

        // Execute protocol enumeration
        let protocol_results = tester.test_all_protocols().await?;

        // Store results in context
        context.results.protocols = protocol_results;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn build_context(args: ScanRequest) -> ScanContext {
        let target = crate::utils::network::Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .expect("test assertion should succeed");
        ScanContext::new(target, Arc::new(args), None, None)
    }

    #[test]
    fn test_protocol_phase_should_run() {
        let phase = ProtocolPhase::new();

        // Test with --protocols flag
        let mut args = ScanRequest::default();
        args.scan.proto.enabled = true;
        assert!(phase.should_run(&args));

        // Test with --all flag
        let mut args = ScanRequest::default();
        args.scan.scope.all = true;
        assert!(phase.should_run(&args));

        // Target alone should not imply baseline scanning
        let args = ScanRequest {
            target: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(!phase.should_run(&args));

        // Test with no relevant flags
        let args = ScanRequest::default();
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_protocol_phase_name() {
        let phase = ProtocolPhase::new();
        assert_eq!(phase.name(), "Testing SSL/TLS Protocols");
    }

    #[test]
    fn test_protocol_phase_configure_tester_branches() {
        let mut args = ScanRequest::default();
        args.starttls.smtp = true;
        args.starttls.rdp = true;
        args.tls.bugs = true;
        args.tls.sni_name = Some("sni.example".to_string());
        args.scan.proto.tls12 = true;
        args.network.test_all_ips = true;

        let context = build_context(args);
        let phase = ProtocolPhase::new();
        let _tester = phase.configure_tester(&context);
    }

    #[test]
    fn test_protocol_phase_default_name() {
        let phase: ProtocolPhase = Default::default();
        assert_eq!(phase.name(), "Testing SSL/TLS Protocols");
    }
}
