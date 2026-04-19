use super::{ClientSimulationResult, ScannerFormatter};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    /// Display client simulation results
    pub fn display_client_simulation_results(&self, results: &[ClientSimulationResult]) {
        self.print_section("Client Simulation:", 50);

        let mut successful = 0;
        let mut failed = 0;

        for result in results {
            if result.is_success() {
                successful += 1;
                self.display_successful_client_sim(result);
            } else {
                failed += 1;
                self.display_failed_client_sim(result);
            }
        }

        self.display_client_sim_totals(results.len(), successful, failed);
    }

    /// Display successful client simulation
    fn display_successful_client_sim(&self, result: &ClientSimulationResult) {
        let handshake_time = result
            .handshake_time_ms
            .map(|ms| format!(" ({}ms)", ms))
            .unwrap_or_default();

        println!(
            "  {} {} - {} / {}{}",
            "Y".green(),
            result.client_name.cyan(),
            result
                .protocol
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            result.cipher.as_ref().unwrap_or(&"Unknown".to_string()),
            handshake_time.dimmed()
        );
    }

    /// Display failed client simulation
    fn display_failed_client_sim(&self, result: &ClientSimulationResult) {
        println!(
            "  {} {} - {}",
            "X".red(),
            result.client_name.cyan(),
            result
                .error
                .as_ref()
                .unwrap_or(&"Connection failed".to_string())
                .red()
        );
    }

    /// Display client simulation totals
    fn display_client_sim_totals(&self, total: usize, successful: usize, failed: usize) {
        println!("\n{}", self.divider(50));
        println!(
            "  Total: {} | {} Successful | {} Failed",
            total,
            successful.to_string().green(),
            failed.to_string().red()
        );

        if successful == total {
            println!(
                "\n{}",
                "  Y All clients can connect successfully!".green().bold()
            );
        } else if failed == total {
            println!("\n{}", "  X No clients can connect!".red().bold());
        }
    }
}
