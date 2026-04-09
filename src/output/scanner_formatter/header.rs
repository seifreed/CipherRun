use super::ScannerFormatter;
use crate::utils::network::{canonical_target, display_target_host};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    pub fn print_scan_header(&self, hostname: &str, port: u16, starttls_protocol: Option<&str>) {
        let target_display = if self.args.output_presentation_mode().is_response_only() {
            display_target_host(hostname)
        } else {
            canonical_target(hostname, port)
        };

        if let Some(starttls_proto) = starttls_protocol {
            println!(
                "\n{} {} ({})\n",
                "Starting scan of".cyan().bold(),
                target_display.green().bold(),
                format!("STARTTLS {}", starttls_proto).yellow()
            );
            println!(
                "  {} STARTTLS negotiation will be performed before TLS handshake",
                "i".cyan()
            );
        } else {
            println!(
                "\n{} {}\n",
                "Starting scan of".cyan().bold(),
                target_display.green().bold()
            );
        }
    }

    pub fn print_phase_progress(&self, message: &str) {
        println!("{}", message.yellow().bold());
    }

    pub fn print_phase_progress_nl(&self, message: &str) {
        println!("\n{}", message.yellow().bold());
    }

    pub fn print_error(&self, message: &str) {
        println!("  {}", message.red());
    }
}
