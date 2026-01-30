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
// - Args (CLI configuration)
// - Target (server information)
//
// Client types simulated:
// - Modern browsers (Chrome, Firefox, Safari, Edge)
// - Legacy browsers (IE 11, old mobile browsers)
// - Operating systems (Windows, macOS, Linux, iOS, Android)
// - API clients (curl, wget, Java, Python)

use super::{ScanContext, ScanPhase};
use crate::client_sim::simulator::ClientSimulator;
use crate::{Args, Result};
use async_trait::async_trait;

/// Client simulation phase
///
/// Simulates connections from various popular TLS clients to determine
/// which clients can successfully connect to the target server. This helps
/// identify compatibility issues with legacy clients or modern security
/// requirements.
///
/// Configuration sources (from Args):
/// - Full scan mode (--all) enables client simulation
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

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Full scan mode (--all)
        args.scan.all
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
    fn test_client_sim_phase_name() {
        let phase = ClientSimPhase::new();
        assert_eq!(phase.name(), "Simulating Client Connections");
    }
}
