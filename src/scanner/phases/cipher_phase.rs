// Cipher Suite Testing Phase - Tests supported cipher suites per protocol
//
// This phase is responsible for enumerating which cipher suites are supported
// by the target server for each supported protocol. It depends on ProtocolPhase
// completing first to know which protocols to test.
//
// Responsibilities (Single Responsibility Principle):
// - Configure cipher tester with CLI arguments
// - Test ciphers only for supported protocols
// - Store results in scan context
// - Handle rate limiting and retry logic
//
// Dependencies:
// - CipherTester (domain logic for cipher enumeration)
// - Args (CLI configuration for timeouts, concurrency, retries)
// - ProtocolTestResult (determines which protocols to test)

use super::{ScanContext, ScanPhase};
use crate::ciphers::tester::CipherTester;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::{Args, Result};
use async_trait::async_trait;
use std::collections::HashMap;

/// Cipher suite testing phase
///
/// Tests which cipher suites are supported for each protocol discovered
/// by ProtocolPhase. This is typically the most time-consuming phase
/// as it performs hundreds of individual cipher tests.
///
/// Configuration sources (from Args):
/// - Connection timeout (--connect-timeout)
/// - Sleep between requests (--sleep)
/// - Max concurrent tests (--max-concurrent-ciphers)
/// - Retry configuration (--max-retries, --retry-backoff)
/// - STARTTLS protocol (--starttls-*)
/// - RDP mode (--rdp)
/// - Multi-IP testing (--test-all-ips)
///
/// Performance optimizations:
/// - Concurrent cipher testing (default: 10 parallel tests)
/// - Configurable rate limiting (--sleep)
/// - Exponential backoff retry for transient failures
/// - Skips QUIC protocol (not yet supported)
pub struct CipherPhase;

impl CipherPhase {
    /// Create a new cipher testing phase
    pub fn new() -> Self {
        Self
    }

    /// Configure CipherTester with CLI arguments
    ///
    /// This method implements the Builder Pattern to construct a properly
    /// configured CipherTester based on CLI flags. It centralizes all
    /// cipher testing configuration logic in one place.
    ///
    /// Configuration priorities:
    /// 1. Performance: Timeouts and concurrency limits
    /// 2. Reliability: Retry logic for handling network saturation
    /// 3. Protocol-specific: STARTTLS, RDP, multi-IP support
    ///
    /// Design note: Aggressive timeouts and retries are used because
    /// cipher testing generates high network load which can trigger
    /// rate limiting or transient failures (ENETDOWN, EAGAIN).
    fn configure_tester(&self, context: &ScanContext) -> CipherTester {
        let target = context.target();
        let mut tester = CipherTester::new(target);

        // Apply connect timeout if specified
        // Default is typically 5 seconds, can be lowered for faster scans
        // or increased for high-latency connections
        if let Some(timeout_secs) = context.args.connection.connect_timeout {
            tester = tester.with_connect_timeout(std::time::Duration::from_secs(timeout_secs));
        }

        // Apply sleep duration if specified
        // Adds delay between cipher tests to avoid overwhelming the server
        // or triggering IDS/IPS alerts. Use --sleep 1000 for IDS-friendly scanning.
        if let Some(sleep_ms) = context.args.connection.sleep {
            tester = tester.with_sleep(std::time::Duration::from_millis(sleep_ms));
        }

        // Apply max concurrent cipher tests if specified
        // Lower values (5-10) reduce network load and prevent "Network is down" errors
        // Higher values (20-50) speed up scanning but may trigger rate limiting
        // Default: 10 (balanced between speed and reliability)
        tester = tester.with_max_concurrent_tests(context.args.network.max_concurrent_ciphers);

        // Apply retry configuration for handling network saturation
        // Retries help distinguish transient failures (timeout, reset) from
        // permanent failures (connection refused, no route to host)
        //
        // Retryable errors: ENETDOWN, EAGAIN, ETIMEDOUT, ECONNRESET
        // Non-retryable errors: ECONNREFUSED, EHOSTUNREACH, EINVAL
        if let Some(retry_config) = context.args.retry_config() {
            tester = tester.with_retry_config(Some(retry_config));
        }

        // Enable RDP mode if specified
        // RDP requires special TLS negotiation sequence
        if context.args.starttls.rdp {
            tester = tester.with_rdp(true);
        }

        // Enable STARTTLS if specified
        // Must perform application protocol handshake before TLS
        if let Some(starttls_proto) = context.args.starttls_protocol() {
            tester = tester.with_starttls(Some(starttls_proto));
        }

        // Enable testing all IPs if specified
        // Tests ciphers on each resolved IP address independently
        if context.args.network.test_all_ips {
            tester = tester.with_test_all_ips(true);
        }

        tester
    }

    /// Test ciphers for supported protocols only
    ///
    /// Filters protocol results to only test protocols that:
    /// 1. Are marked as supported (protocol_result.supported == true)
    /// 2. Are not QUIC (QUIC cipher testing not yet implemented)
    ///
    /// Returns a HashMap mapping Protocol -> ProtocolCipherSummary
    async fn test_supported_protocols(
        &self,
        tester: &CipherTester,
        protocol_results: &[ProtocolTestResult],
    ) -> Result<HashMap<Protocol, crate::ciphers::tester::ProtocolCipherSummary>> {
        let mut results = HashMap::new();

        for protocol_result in protocol_results {
            // Skip unsupported protocols and QUIC
            if !protocol_result.supported || matches!(protocol_result.protocol, Protocol::QUIC) {
                continue;
            }

            // Test ciphers for this protocol
            let summary = tester
                .test_protocol_ciphers(protocol_result.protocol)
                .await?;

            // Only store results if ciphers were found
            // Empty cipher list indicates protocol handshake failed
            if !summary.supported_ciphers.is_empty() {
                results.insert(protocol_result.protocol, summary);
            }
        }

        Ok(results)
    }
}

impl Default for CipherPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for CipherPhase {
    fn name(&self) -> &'static str {
        "Testing Cipher Suites"
    }

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Cipher testing not explicitly disabled (--no-ciphersuites)
        // - AND one of:
        //   - Explicit cipher testing requested (--each-cipher)
        //   - Full scan mode (--all)
        //   - Default scan (target specified without other flags)
        !args.scan.no_ciphersuites
            && (args.scan.each_cipher || args.scan.all || args.target.is_some())
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Cipher testing requires protocol results from previous phase
        // If no protocols were tested, skip cipher phase
        if context.results.protocols.is_empty() {
            return Ok(());
        }

        // Configure tester with all CLI options
        let tester = self.configure_tester(context);

        // Test ciphers only for supported protocols
        let cipher_results = self
            .test_supported_protocols(&tester, &context.results.protocols)
            .await?;

        // Store results in context
        context.results.ciphers = cipher_results;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_cipher_phase_should_run() {
        let phase = CipherPhase::new();

        // Test with --each-cipher flag
        let mut args = Args::default();
        args.scan.each_cipher = true;
        assert!(phase.should_run(&args));

        // Test with --all flag
        let mut args = Args::default();
        args.scan.all = true;
        assert!(phase.should_run(&args));

        // Test with target specified (default scan)
        let mut args = Args::default();
        args.target = Some("example.com".to_string());
        assert!(phase.should_run(&args));

        // Test with --no-ciphersuites (should not run)
        let mut args = Args::default();
        args.scan.all = true;
        args.scan.no_ciphersuites = true;
        assert!(!phase.should_run(&args));

        // Test with no relevant flags
        let args = Args::default();
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_cipher_phase_name() {
        let phase = CipherPhase::new();
        assert_eq!(phase.name(), "Testing Cipher Suites");
    }
}
