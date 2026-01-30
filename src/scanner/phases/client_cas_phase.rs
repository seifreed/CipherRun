// Client CAs Phase - Extracts list of accepted client certificate authorities
//
// This phase extracts the list of Certificate Authorities (CAs) that the
// target server accepts for client certificate authentication. This is
// relevant for servers configured to request or require client certificates
// (mutual TLS / mTLS).
//
// Responsibilities (Single Responsibility Principle):
// - Configure client CA tester
// - Execute client CA enumeration
// - Store client CA list in scan context
//
// Dependencies:
// - ClientCAsTester (domain logic for CA list extraction)
// - Args (CLI configuration)
// - Target (server information)
//
// Information extracted:
// - List of Distinguished Names (DNs) of accepted CAs
// - Number of accepted CAs
// - CA organizational information
// - Whether client certificates are requested vs. required

use super::{ScanContext, ScanPhase};
use crate::protocols::client_cas::ClientCAsTester;
use crate::{Args, Result};
use async_trait::async_trait;

/// Client CAs enumeration phase
///
/// Extracts the list of Certificate Authorities that the target server
/// accepts for client certificate authentication. This information is
/// only available when the server requests or requires client certificates
/// during the TLS handshake.
///
/// Configuration sources (from Args):
/// - Client CA enumeration flag (--show-client-cas)
/// - Target information (hostname, port, resolved IPs)
pub struct ClientCasPhase;

impl ClientCasPhase {
    /// Create a new client CAs enumeration phase
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClientCasPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for ClientCasPhase {
    fn name(&self) -> &'static str {
        "Extracting Client CAs List"
    }

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Explicit client CA enumeration requested (--show-client-cas)
        args.scan.show_client_cas
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create client CA tester with target
        let tester = ClientCAsTester::new(context.target());

        // Enumerate accepted client CAs
        // This extracts:
        // 1. List of CA Distinguished Names (DNs)
        // 2. Whether client certificates are required or optional
        // 3. CA organizational information
        let client_cas_results = tester.enumerate_client_cas().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.advanced_mut().client_cas = Some(client_cas_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_cas_phase_should_run() {
        let phase = ClientCasPhase::new();

        // Test with --show-client-cas flag
        let mut args = Args::default();
        args.scan.show_client_cas = true;
        assert!(phase.should_run(&args));

        // Test without --show-client-cas flag
        let args = Args::default();
        assert!(!phase.should_run(&args));

        // Test with --all flag (should not enable client CA enumeration)
        let mut args = Args::default();
        args.scan.all = true;
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_client_cas_phase_name() {
        let phase = ClientCasPhase::new();
        assert_eq!(phase.name(), "Extracting Client CAs List");
    }
}
