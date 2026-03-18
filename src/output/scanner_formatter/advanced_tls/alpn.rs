use super::super::{AlpnReport, ScannerFormatter, print_section_header};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    pub fn display_alpn_results(&self, alpn_report: &AlpnReport) {
        print_section_header("ALPN Protocol Negotiation:");

        if alpn_report.alpn_enabled {
            println!("  {} ALPN is enabled", "Y".green().bold());
            self.display_alpn_protocols(alpn_report);
        } else {
            println!(
                "  {} ALPN is not enabled or no protocols supported",
                "X".red()
            );
        }

        self.display_alpn_recommendations(alpn_report);
    }

    fn display_alpn_protocols(&self, alpn_report: &AlpnReport) {
        if !alpn_report.alpn_result.supported_protocols.is_empty() {
            println!("\n  Supported Protocols:");
            for proto in &alpn_report.alpn_result.supported_protocols {
                println!("    - {}", proto.green());
            }

            if let Some(ref negotiated) = alpn_report.alpn_result.negotiated_protocol {
                println!("\n  Server Preferred: {}", negotiated.cyan().bold());
            }
        }

        if alpn_report.alpn_result.http2_supported {
            println!("\n  {} HTTP/2 (h2) is supported", "Y".green().bold());
        }

        if alpn_report.alpn_result.http3_supported {
            println!("\n  {} HTTP/3 (h3) is supported", "Y".green().bold());
        }
    }

    fn display_alpn_recommendations(&self, alpn_report: &AlpnReport) {
        if !alpn_report.recommendations.is_empty() {
            println!("\n  Recommendations:");
            for rec in &alpn_report.recommendations {
                println!("    - {}", rec.yellow());
            }
        }
    }
}
