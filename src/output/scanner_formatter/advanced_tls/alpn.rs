use super::super::{AlpnReport, ScannerFormatter};
use colored::Colorize;
impl<'a> ScannerFormatter<'a> {
    pub fn display_alpn_results(&self, alpn_report: &AlpnReport) {
        self.print_section("ALPN Protocol Negotiation:", 50);

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

#[cfg(test)]
mod tests {
    use super::ScannerFormatter;
    use crate::cli::Args;
    use crate::protocols::alpn::{AlpnReport, AlpnResult};

    fn report(
        enabled: bool,
        protocols: Vec<&str>,
        negotiated: Option<&str>,
        http2: bool,
        http3: bool,
        recommendations: Vec<&str>,
    ) -> AlpnReport {
        AlpnReport {
            alpn_enabled: enabled,
            alpn_result: AlpnResult {
                supported_protocols: protocols.into_iter().map(str::to_string).collect(),
                http2_supported: http2,
                http3_supported: http3,
                negotiated_protocol: negotiated.map(str::to_string),
                details: Vec::new(),
                inconclusive: false,
            },
            spdy_supported: false,
            recommendations: recommendations.into_iter().map(str::to_string).collect(),
            inconclusive: false,
        }
    }

    #[test]
    fn display_alpn_results_handles_disabled_empty_and_populated_reports() {
        colored::control::set_override(false);
        let args = Args::default();
        let formatter = ScannerFormatter::new(&args);

        formatter.display_alpn_results(&report(false, Vec::new(), None, false, false, Vec::new()));
        formatter.display_alpn_results(&report(true, Vec::new(), None, false, false, Vec::new()));
        formatter.display_alpn_results(&report(
            true,
            vec!["http/1.1"],
            None,
            false,
            false,
            Vec::new(),
        ));
        formatter.display_alpn_results(&report(
            true,
            vec!["h2", "h3"],
            Some("h3"),
            true,
            true,
            vec!["Enable HTTP/2 and HTTP/3"],
        ));
    }
}
