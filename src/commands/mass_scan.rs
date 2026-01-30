// MassScanCommand - Mass scanning from input file
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
use crate::{Args, Result, TlsError};
use async_trait::async_trait;
use colored::Colorize;
use tracing::info;

/// MassScanCommand handles mass scanning from an input file
///
/// This command is responsible for:
/// - Loading targets from an input file
/// - Scanning multiple targets in parallel or serial mode
/// - Applying certificate validation filters
/// - Generating summary reports
/// - Exporting results to various formats
pub struct MassScanCommand {
    args: Args,
}

impl MassScanCommand {
    /// Create a new MassScanCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

#[async_trait]
impl Command for MassScanCommand {
    async fn execute(&self) -> Result<()> {
        use crate::scanner::mass::MassScanner;

        let input_file = self
            .args
            .input_file
            .as_ref()
            .ok_or_else(|| TlsError::InvalidInput {
                message: "Input file is required for mass scanning".to_string(),
            })?;

        let input_file_str = input_file.to_str().ok_or_else(|| TlsError::InvalidInput {
            message: "Invalid input file path".to_string(),
        })?;

        let mass_scanner = MassScanner::from_file(self.args.clone(), input_file_str)?;

        info!(
            "Loaded {} targets from {}",
            mass_scanner.targets.len(),
            input_file.display()
        );

        let results = if self.args.network.parallel {
            mass_scanner.scan_parallel().await?
        } else {
            mass_scanner.scan_serial().await?
        };

        // Apply certificate filters if active
        let filtered_results = MassScanner::filter_results(&self.args, results);

        // Display filter status if filters were applied
        if self.args.has_certificate_filters() {
            let mut filter_names = Vec::new();
            if self.args.cert_filters.filter_expired {
                filter_names.push("expired");
            }
            if self.args.cert_filters.filter_self_signed {
                filter_names.push("self-signed");
            }
            if self.args.cert_filters.filter_mismatched {
                filter_names.push("mismatched");
            }
            if self.args.cert_filters.filter_revoked {
                filter_names.push("revoked");
            }
            if self.args.cert_filters.filter_untrusted {
                filter_names.push("untrusted");
            }

            println!(
                "\n{} Applied certificate filters: {}",
                "".cyan(),
                filter_names.join(", ")
            );
            println!(
                "{} Showing {} of {} targets that match filter criteria\n",
                "".cyan(),
                filtered_results.len(),
                mass_scanner.targets.len()
            );
        }

        // Display summary
        println!("{}", MassScanner::generate_summary(&filtered_results));

        // Export if requested (use filtered results)
        if let Some(json_file) = &self.args.output.json {
            let json_file_str = json_file.to_str().ok_or_else(|| TlsError::InvalidInput {
                message: "Invalid JSON output file path".to_string(),
            })?;
            MassScanner::export_all_json(
                &filtered_results,
                json_file_str,
                self.args.output.json_pretty,
            )?;
            println!("✓ Results exported to JSON: {}", json_file.display());
        }

        if self.args.output.csv.is_some() || self.args.output.html.is_some() {
            println!(
                "Note: CSV and HTML export for mass scans will export individual results per target"
            );
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "MassScanCommand"
    }
}
