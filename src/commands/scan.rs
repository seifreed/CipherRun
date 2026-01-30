// ScanCommand - Single target TLS/SSL scanning
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
use crate::{Args, Result};
use async_trait::async_trait;

/// ScanCommand handles single target TLS/SSL security scanning
///
/// This command is responsible for:
/// - Scanning a single target (hostname:port)
/// - Running all requested security tests
/// - Evaluating compliance frameworks if requested
/// - Evaluating policy-as-code if requested
/// - Storing results in database if requested
/// - Exporting results to various formats (JSON, CSV, HTML, XML)
pub struct ScanCommand {
    args: Args,
}

impl ScanCommand {
    /// Create a new ScanCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

#[async_trait]
impl Command for ScanCommand {
    async fn execute(&self) -> Result<()> {
        use crate::Scanner;

        // Create scanner
        let scanner = Scanner::new(self.args.clone())?;

        // Run the scan
        let results = scanner.run().await?;

        // Format and display results (presentation layer)
        use crate::output::ScannerFormatter;
        let formatter = ScannerFormatter::new(&self.args);

        // Display individual phase results if they exist
        if !results.protocols.is_empty() {
            formatter.display_protocol_results(&results.protocols);
        }
        if !results.ciphers.is_empty() {
            formatter.display_cipher_results(&results.ciphers);
        }
        if let Some(ref cert_data) = results.certificate_chain {
            formatter.display_certificate_results(cert_data);
        }
        if let Some(headers) = results.http_headers() {
            formatter.display_http_headers_results(headers);
        }
        if !results.vulnerabilities.is_empty() {
            formatter.display_vulnerability_results(&results.vulnerabilities);
        }
        if let Some(sims) = results.client_simulations() {
            formatter.display_client_simulation_results(sims);
        }
        if let Some(sigs) = results.signature_algorithms() {
            formatter.display_signature_results(sigs);
        }
        if let Some(groups) = results.key_exchange_groups() {
            formatter.display_group_results(groups);
        }
        if let Some(cas) = results.client_cas() {
            formatter.display_client_cas_results(cas);
        }
        if let Some(intolerance) = results.intolerance() {
            formatter.display_intolerance_results(intolerance);
        }
        if let Some(ja3) = results.ja3_fingerprint() {
            formatter.display_ja3_results(ja3, results.ja3_match());
        }
        if let Some(ja3s) = results.ja3s_fingerprint() {
            formatter.display_ja3s_results(ja3s, results.ja3s_match());
        }
        if let Some(jarm) = results.jarm_fingerprint() {
            formatter.display_jarm_results(jarm);
        }
        if let Some(alpn) = results.alpn_result() {
            formatter.display_alpn_results(alpn);
        }
        if let Some(rating) = results.ssl_rating() {
            formatter.display_rating_results(rating);
        }

        // Display summary (presentation layer)
        formatter.display_results_summary(&results);

        // Evaluate compliance if requested
        if let Some(framework_id) = &self.args.compliance.framework {
            use crate::compliance::{
                ComplianceEngine, ComplianceStatus, FrameworkLoader, Reporter,
            };
            use colored::Colorize;

            println!("\n{}", "Evaluating Compliance...".cyan().bold());

            // Load the framework
            let framework = FrameworkLoader::load_builtin(framework_id)?;

            // Create engine and evaluate
            let engine = ComplianceEngine::new(framework);
            let report = engine.evaluate(&results)?;

            // Display report based on format
            match self.args.compliance.format.to_lowercase().as_str() {
                "json" => {
                    let json = Reporter::to_json(&report, self.args.output.json_pretty)?;
                    println!("{}", json);
                }
                "csv" => {
                    let csv = Reporter::to_csv(&report)?;
                    println!("{}", csv);
                }
                "html" => {
                    let html = Reporter::to_html(&report)?;
                    println!("{}", html);
                }
                _ => {
                    // Terminal output (default)
                    let terminal_output = Reporter::to_terminal(&report);
                    println!("{}", terminal_output);
                }
            }

            // Exit with error code if compliance failed
            if report.overall_status == ComplianceStatus::Fail {
                std::process::exit(1);
            }
        }

        // Evaluate policy if requested
        if let Some(policy_path) = &self.args.compliance.policy {
            use crate::policy::evaluator::PolicyEvaluator;
            use crate::policy::parser::PolicyLoader;

            println!("\nEvaluating Policy...");

            let loader = PolicyLoader::new(
                policy_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(".")),
            );
            let policy = loader.load(policy_path)?;

            let evaluator = PolicyEvaluator::new(policy);
            let policy_result = evaluator.evaluate(&results)?;

            // Display policy result
            let formatted_result = policy_result.format(&self.args.compliance.policy_format)?;
            println!("{}", formatted_result);

            // Exit with error code if --enforce is set and violations found
            if self.args.compliance.enforce && policy_result.has_violations() {
                eprintln!("\nPolicy evaluation failed - exiting with error code 1");
                std::process::exit(1);
            }
        }

        // Store results in database if requested
        if self.args.database.store_results && self.args.database.config.is_some() {
            use crate::db::CipherRunDatabase;
            use crate::utils::PathExt;

            let db_config_path = self
                .args
                .database
                .config
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Database config path not provided"))?
                .to_str_anyhow()?;

            let db = CipherRunDatabase::from_config_file(db_config_path).await?;
            let scan_id = db.store_scan(&results).await?;
            println!("\n✓ Scan results stored in database (scan_id: {})", scan_id);
            db.close().await;
        }

        // Export results if requested
        if let Some(json_file) = &self.args.output.json {
            let json = results.to_json(self.args.output.json_pretty)?;
            std::fs::write(json_file, &json)?;
            println!("✓ Results exported to JSON: {}", json_file.display());
        }

        // Export multi-IP report to JSON if requested (presentation layer responsibility)
        if let Some(json_path) = &self.args.output.json_multi_ip
            && let Some(ref report) = results.multi_ip_report {
                use crate::output::json::generate_multi_ip_json;
                let json = generate_multi_ip_json(report, self.args.output.json_pretty)?;
                std::fs::write(json_path, &json)?;
                println!(
                    "✓ Multi-IP report exported to JSON: {}",
                    json_path.display()
                );
            }

        if let Some(csv_file) = &self.args.output.csv {
            let csv = results.to_csv()?;
            std::fs::write(csv_file, &csv)?;
            println!("✓ Results exported to CSV: {}", csv_file.display());
        }

        if let Some(html_file) = &self.args.output.html {
            use crate::output::html;
            let html_content = html::generate_html_report(&results)?;
            std::fs::write(html_file, &html_content)?;
            println!("✓ Results exported to HTML: {}", html_file.display());
        }

        if let Some(xml_file) = &self.args.output.xml {
            use crate::output::xml;
            let xml_content = xml::generate_xml_report(&results)?;
            std::fs::write(xml_file, &xml_content)?;
            println!("✓ Results exported to XML: {}", xml_file.display());
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ScanCommand"
    }
}
