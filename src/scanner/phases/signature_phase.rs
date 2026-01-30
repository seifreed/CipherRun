// Signature Algorithm Enumeration Phase - Tests signature algorithm support
//
// This phase enumerates the signature algorithms supported by the target server
// for certificate verification during the TLS handshake. Signature algorithms
// determine how certificates are validated (RSA, ECDSA, EdDSA) and which hash
// functions are used (SHA-256, SHA-384, SHA-512).
//
// Responsibilities (Single Responsibility Principle):
// - Configure signature algorithm tester
// - Execute signature algorithm enumeration
// - Store signature algorithm results in scan context
//
// Dependencies:
// - SignatureTester (domain logic for signature algorithm testing)
// - Args (CLI configuration)
// - Target (server information)
//
// Signature algorithms tested:
// - RSA with various hash algorithms (SHA-256, SHA-384, SHA-512)
// - ECDSA with various curves (P-256, P-384, P-521)
// - EdDSA (Ed25519, Ed448)
// - Legacy algorithms (RSA-SHA1, RSA-MD5 - deprecated)

use super::{ScanContext, ScanPhase};
use crate::protocols::signatures::SignatureTester;
use crate::{Args, Result};
use async_trait::async_trait;

/// Signature algorithm enumeration phase
///
/// Tests which signature algorithms are supported by the target server
/// for certificate validation during the TLS handshake. This information
/// is useful for understanding server capabilities and identifying
/// potential compatibility or security issues.
///
/// Configuration sources (from Args):
/// - Signature enumeration flag (--show-sigs)
/// - Target information (hostname, port, resolved IPs)
pub struct SignaturePhase;

impl SignaturePhase {
    /// Create a new signature algorithm enumeration phase
    pub fn new() -> Self {
        Self
    }
}

impl Default for SignaturePhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for SignaturePhase {
    fn name(&self) -> &'static str {
        "Enumerating Signature Algorithms"
    }

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Explicit signature enumeration requested (--show-sigs)
        args.scan.show_sigs
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create signature tester with target
        let tester = SignatureTester::new(context.target());

        // Enumerate all supported signature algorithms
        // This tests:
        // 1. RSA signature algorithms (various hash functions)
        // 2. ECDSA signature algorithms (various curves)
        // 3. EdDSA signature algorithms (Ed25519, Ed448)
        // 4. Legacy algorithms (RSA-SHA1, RSA-MD5)
        let signature_results = tester.enumerate_signatures().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.advanced_mut().signature_algorithms = Some(signature_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_phase_should_run() {
        let phase = SignaturePhase::new();

        // Test with --show-sigs flag
        let mut args = Args::default();
        args.scan.show_sigs = true;
        assert!(phase.should_run(&args));

        // Test without --show-sigs flag
        let args = Args::default();
        assert!(!phase.should_run(&args));

        // Test with --all flag (should not enable signature enumeration)
        let mut args = Args::default();
        args.scan.all = true;
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_signature_phase_name() {
        let phase = SignaturePhase::new();
        assert_eq!(phase.name(), "Enumerating Signature Algorithms");
    }
}
