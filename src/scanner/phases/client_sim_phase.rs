// Client Simulation Phase - Tests TLS client compatibility
//
// This phase simulates connections from popular clients (browsers, operating
// systems, mobile devices) to assess compatibility and identify which clients
// can successfully connect to the target server.
//
// Responsibilities (Single Responsibility Principle):
// - Configure client simulator
// - Execute popular client simulations
// - Store client simulation results in scan context
//
// Dependencies:
// - ClientSimulator (domain logic for client simulation)
// - ScanRequest (scan configuration)
// - Target (server information)
//
// Client types simulated:
// - Modern browsers (Chrome, Firefox, Safari, Edge)
// - Legacy browsers (IE 11, old mobile browsers)
// - Operating systems (Windows, macOS, Linux, iOS, Android)
// - API clients (curl, wget, Java, Python)

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use crate::client_sim::simulator::ClientSimulator;
use async_trait::async_trait;

/// Client simulation phase
///
/// Simulates connections from various popular TLS clients to determine
/// which clients can successfully connect to the target server. This helps
/// identify compatibility issues with legacy clients or modern security
/// requirements.
///
/// Configuration sources (from ScanRequest):
/// - Explicit client simulation flag (-c/--client-simulation)
/// - Baseline scan policy enables implicit client simulation
/// - Target information (hostname, port, resolved IPs)
pub struct ClientSimPhase;

impl ClientSimPhase {
    /// Create a new client simulation phase
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClientSimPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for ClientSimPhase {
    fn name(&self) -> &'static str {
        "Simulating Client Connections"
    }

    fn should_run(&self, args: &ScanRequest) -> bool {
        // Run if:
        // - Explicit client simulation requested
        // - Baseline scan policy enables implicit client simulation
        args.should_run_client_simulation_phase()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create client simulator with target
        let simulator = ClientSimulator::new(context.target());

        // Simulate popular clients for faster scanning
        // This tests a representative sample of:
        // - Modern browsers (latest Chrome, Firefox, Safari)
        // - Legacy browsers (IE 11, old Android)
        // - Mobile devices (iOS, Android)
        // - API clients (curl, Java, Python)
        let simulation_results = simulator.simulate_popular_clients().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.advanced_mut().client_simulations = Some(simulation_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_sim_phase_should_run() {
        let phase = ClientSimPhase::new();

        // Test with baseline
        let mut args = ScanRequest::default();
        args.scan.scope.all = true;
        assert!(phase.should_run(&args));

        // Test with explicit client simulation and baseline disabled
        let mut args = ScanRequest::default();
        args.scan.scope.all = false;
        args.fingerprint.client_simulation = true;
        assert!(phase.should_run(&args));

        // Specific-focus scans should not implicitly enable client simulation.
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
    fn test_client_sim_phase_name() {
        let phase = ClientSimPhase::new();
        assert_eq!(phase.name(), "Simulating Client Connections");
    }

    #[test]
    fn test_client_sim_phase_default() {
        let phase: ClientSimPhase = Default::default();
        assert_eq!(phase.name(), "Simulating Client Connections");
    }
}
