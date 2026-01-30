// Key Exchange Groups Phase - Tests supported key exchange groups
//
// This phase enumerates the key exchange groups (named curves for ECDHE,
// finite field groups for DHE) supported by the target server. These groups
// determine the cryptographic strength of the key exchange and forward secrecy.
//
// Responsibilities (Single Responsibility Principle):
// - Configure key exchange group tester
// - Execute group enumeration
// - Store group enumeration results in scan context
//
// Dependencies:
// - GroupTester (domain logic for group enumeration)
// - Args (CLI configuration)
// - Target (server information)
//
// Groups tested:
// - Elliptic curves (secp256r1/P-256, secp384r1/P-384, secp521r1/P-521)
// - Modern curves (X25519, X448)
// - Legacy curves (secp224r1, prime256v1)
// - Finite field DH groups (ffdhe2048, ffdhe3072, ffdhe4096)

use super::{ScanContext, ScanPhase};
use crate::protocols::groups::GroupTester;
use crate::{Args, Result};
use async_trait::async_trait;

/// Key exchange groups enumeration phase
///
/// Tests which elliptic curve groups and finite field DH groups are
/// supported by the target server for key exchange. This information
/// helps assess the cryptographic strength of the key exchange mechanism
/// and forward secrecy capabilities.
///
/// Configuration sources (from Args):
/// - Group enumeration flag (--show-groups)
/// - Group exclusion flag (--no-groups)
/// - Target information (hostname, port, resolved IPs)
pub struct GroupsPhase;

impl GroupsPhase {
    /// Create a new key exchange groups enumeration phase
    pub fn new() -> Self {
        Self
    }
}

impl Default for GroupsPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for GroupsPhase {
    fn name(&self) -> &'static str {
        "Enumerating Key Exchange Groups"
    }

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Explicit group enumeration requested (--show-groups)
        // - AND not explicitly disabled (--no-groups)
        args.scan.show_groups && !args.scan.no_groups
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create group tester with target
        let tester = GroupTester::new(context.target());

        // Enumerate all supported key exchange groups
        // This tests:
        // 1. Modern elliptic curves (X25519, X448, P-256, P-384, P-521)
        // 2. Legacy curves (secp224r1, prime256v1)
        // 3. Finite field DH groups (ffdhe2048, ffdhe3072, ffdhe4096, ffdhe8192)
        let group_results = tester.enumerate_groups().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.advanced_mut().key_exchange_groups = Some(group_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groups_phase_should_run() {
        let phase = GroupsPhase::new();

        // Test with --show-groups flag
        let mut args = Args::default();
        args.scan.show_groups = true;
        assert!(phase.should_run(&args));

        // Test with --show-groups but also --no-groups (disabled)
        let mut args = Args::default();
        args.scan.show_groups = true;
        args.scan.no_groups = true;
        assert!(!phase.should_run(&args));

        // Test without --show-groups flag
        let args = Args::default();
        assert!(!phase.should_run(&args));

        // Test with --all flag (should not enable group enumeration)
        let mut args = Args::default();
        args.scan.all = true;
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_groups_phase_name() {
        let phase = GroupsPhase::new();
        assert_eq!(phase.name(), "Enumerating Key Exchange Groups");
    }
}
