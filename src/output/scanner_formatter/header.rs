use super::ScannerFormatter;
use colored::*;

impl<'a> ScannerFormatter<'a> {
    pub fn print_scan_header(&self, hostname: &str, port: u16, starttls_protocol: Option<&str>) {
        if let Some(starttls_proto) = starttls_protocol {
            println!(
                "\n{} {}:{} ({})\n",
                "Starting scan of".cyan().bold(),
                hostname.green().bold(),
                port.to_string().green().bold(),
                format!("STARTTLS {}", starttls_proto).yellow()
            );
            println!(
                "  {} STARTTLS negotiation will be performed before TLS handshake",
                "i".cyan()
            );
        } else {
            println!(
                "\n{} {}:{}\n",
                "Starting scan of".cyan().bold(),
                hostname.green().bold(),
                port.to_string().green().bold()
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
