use super::{
    CertificateAnalysisResult, ClientSimulationResult, Ja3Fingerprint, Ja3Signature, RatingResult,
    ScannerFormatter, format_client_sim_summary, format_http_grade, format_ssl_grade,
};
use crate::fingerprint::{CdnDetection, LoadBalancerInfo};
use crate::http::tester::HeaderAnalysisResult;
use crate::output::probe_status::ProbeStatusTerminalExt;
use crate::utils::network::{display_target_host, split_target_host_port};
use colored::Colorize;
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
        for line in self.cdn_summary_lines(results.cdn_detection(), results.load_balancer_info()) {
            println!("{line}");
        }

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

    fn cdn_summary_lines(
        &self,
        cdn: Option<&CdnDetection>,
        load_balancer: Option<&LoadBalancerInfo>,
    ) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(cdn) = cdn {
            let status = if cdn.is_cdn { "Detected" } else { "No" };
            lines.push(format!("CDN Detection:   {}", status));
        }

        if let Some(load_balancer) = load_balancer {
            let status = if load_balancer.detected {
                "Detected"
            } else {
                "No"
            };
            lines.push(format!("Load Balancer:   {}", status));
        }

        lines
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{CdnDetection, LoadBalancerInfo};

    #[test]
    fn test_cdn_summary_lines_include_detection_and_load_balancer() {
        let args = crate::Args::default();
        let formatter = ScannerFormatter::new(&args);

        let lines = formatter.cdn_summary_lines(
            Some(&CdnDetection {
                is_cdn: true,
                cdn_provider: Some("Cloudflare".to_string()),
                confidence: 0.95,
                indicators: vec!["cf-ray".to_string()],
            }),
            Some(&LoadBalancerInfo {
                detected: true,
                lb_type: Some("AWS ALB".to_string()),
                sticky_sessions: true,
                indicators: vec!["sticky sessions".to_string()],
            }),
        );

        assert_eq!(lines.len(), 2);
        assert!(lines.iter().any(|line| line.contains("CDN Detection")));
        assert!(lines.iter().any(|line| line.contains("Load Balancer")));
    }

    #[test]
    fn summary_displays_handle_response_only_and_batched_warning_modes() {
        let mut response_args = crate::Args::default();
        response_args.cert_filters.response_only = true;
        let response_formatter = ScannerFormatter::new(&response_args);
        let response_results = crate::scanner::ScanResults {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        response_formatter.display_results_summary(&response_results);

        let mut batch_args = crate::Args::default();
        batch_args.output.warnings = Some("batch".to_string());
        let batch_formatter = ScannerFormatter::new(&batch_args);
        batch_formatter.display_batched_warnings(&crate::scanner::ScanResults::default());
        let mut warning_results = crate::scanner::ScanResults::default();
        warning_results.scan_metadata.human_warnings = vec!["fixture warning".to_string()];
        batch_formatter.display_results_summary(&warning_results);
    }

    #[test]
    fn summary_displays_cover_probe_status_and_pre_handshake_paths() {
        let default_args = crate::Args::default();
        let default_formatter = ScannerFormatter::new(&default_args);
        default_formatter.display_probe_summary(&crate::scanner::ScanResults::default());

        let mut args = crate::Args::default();
        args.scan.probe_status = true;
        let formatter = ScannerFormatter::new(&args);
        let mut results = crate::scanner::ScanResults {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        formatter.display_probe_summary(&results);
        results.scan_metadata.pre_handshake_used = true;
        formatter.display_probe_summary(&results);

        args.cert_filters.response_only = true;
        ScannerFormatter::new(&args).display_probe_summary(&results);
    }

    #[test]
    fn summary_displays_cover_certificate_and_client_fingerprint_variants() {
        let args = crate::Args::default();
        let formatter = ScannerFormatter::new(&args);
        formatter.display_certificate_summary(&None);
        formatter.display_certificate_summary(&Some(crate::scanner::CertificateAnalysisResult {
            chain: crate::certificates::parser::CertificateChain {
                certificates: Vec::new(),
                chain_length: 0,
                chain_size_bytes: 0,
            },
            validation: crate::certificates::validator::ValidationResult {
                valid: false,
                issues: Vec::new(),
                trust_chain_valid: false,
                hostname_match: false,
                not_expired: false,
                signature_valid: false,
                trusted_ca: None,
                platform_trust: None,
            },
            revocation: None,
        }));

        let fingerprint = Ja3Fingerprint {
            ja3_string: "771,4865,0,23,0".to_string(),
            ja3_hash: "0123456789abcdef".to_string(),
            ssl_version: 771,
            ciphers: vec![4865],
            extensions: vec![0],
            curves: vec![23],
            point_formats: vec![0],
        };
        for threat_level in ["critical", "medium", "low"] {
            let signature = Ja3Signature {
                name: "fixture client".to_string(),
                category: "test".to_string(),
                description: "fixture".to_string(),
                threat_level: threat_level.to_string(),
            };
            formatter.display_ja3_summary(Some(&fingerprint), Some(&signature));
        }
        formatter.display_ja3_summary(Some(&fingerprint), None);
        formatter.display_ja3_summary(None, None);
    }

    #[test]
    fn summary_displays_cover_negative_load_balancer_and_rating() {
        let args = crate::Args::default();
        let formatter = ScannerFormatter::new(&args);
        let lines = formatter.cdn_summary_lines(
            Some(&CdnDetection {
                is_cdn: false,
                cdn_provider: None,
                confidence: 0.0,
                indicators: Vec::new(),
            }),
            Some(&LoadBalancerInfo {
                detected: false,
                lb_type: None,
                sticky_sessions: false,
                indicators: Vec::new(),
            }),
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("CDN Detection:   No"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Load Balancer:   No"))
        );

        formatter.display_rating_summary(Some(&RatingResult {
            grade: crate::rating::Grade::A,
            score: 95,
            certificate_score: 95,
            protocol_score: 95,
            key_exchange_score: 95,
            cipher_strength_score: 95,
            warnings: Vec::new(),
        }));
        formatter.display_rating_summary(None);
    }
}
