use super::{
    CertificateAnalysisResult, ClientSimulationResult, Ja3Fingerprint, Ja3Signature, RatingResult,
    ScannerFormatter, format_client_sim_summary, format_http_grade, format_ssl_grade,
};
use crate::http::tester::HeaderAnalysisResult;
use crate::output::probe_status::ProbeStatusTerminalExt;
use crate::utils::network::{display_target_host, split_target_host_port};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    /// Display scan results summary
    pub fn display_results_summary(&self, results: &crate::scanner::ScanResults) {
        let presentation_mode = self.args.output_presentation_mode();

        let divider = self.divider(60);
        println!("\n{}", divider.cyan());
        println!("{}", self.section_header("Scan Complete"));
        println!("{}", divider.cyan());
        let target_display = if presentation_mode.is_response_only() {
            split_target_host_port(&results.target)
                .map(|(hostname, _)| display_target_host(&hostname))
                .unwrap_or_else(|_| results.target.clone())
        } else {
            results.target.clone()
        };
        println!("Target:          {}", target_display.green());
        println!("Scan Time:       {} ms", results.scan_time_ms);
        println!("Protocols:       {} tested", results.protocols.len());
        println!(
            "Ciphers:         {} protocols analyzed",
            results.ciphers.len()
        );

        self.display_certificate_summary(&results.certificate_chain);
        self.display_http_headers_summary(results.http_headers());

        println!(
            "Vulnerabilities: {} checks performed",
            results.vulnerabilities.len()
        );
        self.display_probe_summary(results);

        self.display_client_sim_summary(results.client_simulations());
        self.display_rating_summary(results.ssl_rating());
        self.display_ja3_summary(results.ja3_fingerprint(), results.ja3_match());

        if matches!(self.warning_mode(), super::WarningMode::Batch) {
            self.display_batched_warnings(results);
        }

        println!("{}", self.divider(60).cyan());
    }

    /// Display certificate summary in results
    fn display_certificate_summary(&self, cert: &Option<CertificateAnalysisResult>) {
        if let Some(cert) = cert {
            let cert_status = if cert.validation.valid {
                "Valid".green()
            } else {
                "Invalid".red()
            };
            println!(
                "Certificate:     {} ({} certs, {} bytes)",
                cert_status, cert.chain.chain_length, cert.chain.chain_size_bytes
            );
        }
    }

    /// Display HTTP headers summary in results
    fn display_http_headers_summary(&self, headers: Option<&HeaderAnalysisResult>) {
        if let Some(headers) = headers {
            let grade_colored = format_http_grade(&headers.grade);
            println!(
                "HTTP Headers:    {} ({} issues)",
                grade_colored,
                headers.issues.len()
            );
        }
    }

    /// Display client simulation summary in results
    fn display_client_sim_summary(&self, clients: Option<&Vec<ClientSimulationResult>>) {
        if let Some(clients) = clients {
            let successful = clients.iter().filter(|c| c.success).count();
            let status_str = format_client_sim_summary(successful, clients.len());
            println!("Client Sims:     {}", status_str);
        }
    }

    fn display_probe_summary(&self, results: &crate::scanner::ScanResults) {
        if !(self.args.scan.probe_status || results.scan_metadata.pre_handshake_used) {
            return;
        }

        let formatted = results
            .scan_metadata
            .probe_status
            .format_terminal(&results.target);

        if self.args.output_presentation_mode().is_response_only() {
            println!(
                "Probe Status:    {}",
                results.scan_metadata.probe_status.format_response_only()
            );
        } else {
            println!("Probe Status:    {}", formatted);
        }

        if results.scan_metadata.pre_handshake_used {
            println!("Pre-Handshake:   {}", "Y Enabled".green());
        }
    }

    /// Display rating summary in results
    fn display_rating_summary(&self, rating: Option<&RatingResult>) {
        if let Some(rating) = rating {
            let grade_colored = format_ssl_grade(&rating.grade);
            println!("SSL Labs Rating: {} ({}/100)", grade_colored, rating.score);
        }
    }

    /// Display JA3 summary in results
    fn display_ja3_summary(&self, ja3: Option<&Ja3Fingerprint>, ja3_match: Option<&Ja3Signature>) {
        if let Some(ja3) = ja3 {
            let match_str = if let Some(sig) = ja3_match {
                let threat_indicator = match sig.threat_level.as_str() {
                    "critical" | "high" => "!".red().to_string(),
                    "medium" => "!".yellow().to_string(),
                    _ => "Y".green().to_string(),
                };
                format!("{} {}", threat_indicator, sig.name)
                    .cyan()
                    .to_string()
            } else {
                "Unknown client".dimmed().to_string()
            };
            println!("JA3 Fingerprint: {} ({})", ja3.ja3_hash.green(), match_str);
        }
    }

    fn display_batched_warnings(&self, results: &crate::scanner::ScanResults) {
        let warnings = self.collect_human_warnings(results);

        if warnings.is_empty() {
            return;
        }

        println!("\n{}", self.section_header("Warnings"));
        println!("{}", "-".repeat(self.expand_width(50)));
        for warning in warnings {
            println!("  ! {}", warning.yellow());
        }
    }
}
