use super::{ProtocolTestResult, ScannerFormatter, format_status_indicator, format_timing};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    /// Display protocol test results
    pub fn display_protocol_results(&self, results: &[ProtocolTestResult]) {
        println!("\n{}", self.section_header("Protocol Support:"));
        println!("{}", "-".repeat(self.expand_width(50)));

        for result in results {
            self.display_single_protocol_result(result);
        }

        self.display_protocol_features(results);
    }

    /// Display a single protocol test result
    fn display_single_protocol_result(&self, result: &ProtocolTestResult) {
        let status = if result.supported {
            "Supported".green()
        } else if result.inconclusive {
            "Inconclusive".yellow()
        } else {
            "Not supported".red()
        };

        let deprecated = if result.protocol.is_deprecated() {
            " (DEPRECATED)".red()
        } else {
            "".normal()
        };

        let timing = format_timing(self.args.output.show_times, result.handshake_time_ms);
        let check_colored = if result.inconclusive {
            "?".yellow()
        } else {
            format_status_indicator(result.supported)
        };

        println!(
            "  {:<15} {} {}{}{}",
            result.protocol, check_colored, status, deprecated, timing
        );
    }

    /// Display protocol features (heartbeat extension)
    fn display_protocol_features(&self, results: &[ProtocolTestResult]) {
        let supported_protocols = results.iter().filter(|r| r.supported).count();

        if supported_protocols > 0 {
            println!("\n{}", self.section_header("Protocol Features:"));
            println!("{}", "-".repeat(self.expand_width(50)));

            for result in results {
                if result.supported {
                    let heartbeat_status = match result.heartbeat_enabled {
                        Some(true) => "Yes".yellow(),
                        Some(false) => "No".normal(),
                        None => "Inconclusive".yellow(),
                    };
                    println!(
                        "  {:<15} Heartbeat Extension: {}",
                        result.protocol, heartbeat_status
                    );
                }
            }
        }
    }
}
