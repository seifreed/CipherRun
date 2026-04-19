// MassScanCommand - Mass scanning from input file
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::scan_exporter::{ExportKind, ScanExporter};
use super::{Command, CommandExit};
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
/// - Exporting collection results to JSON
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
    async fn execute(&self) -> Result<CommandExit> {
        use crate::scanner::mass::{MassScanConfig, MassScanner};

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

        let scan_request = self.args.to_scan_request();
        let certificate_filters = self.args.to_certificate_filters();
        let mass_scanner = MassScanner::from_file(
            scan_request,
            MassScanConfig {
                max_parallel: self.args.network.max_parallel,
                certificate_filters: certificate_filters.clone(),
            },
            input_file_str,
        )?;

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
        let filtered_results = MassScanner::filter_results(&certificate_filters, results);

        // Display filter status if filters were applied
        if certificate_filters.has_filters() && !self.args.output.quiet {
            println!(
                "\n{} Applied certificate filters: {}",
                "".cyan(),
                certificate_filters.active_filter_names().join(", ")
            );
            println!(
                "{} Showing {} of {} targets that match filter criteria\n",
                "".cyan(),
                filtered_results.len(),
                mass_scanner.targets.len()
            );
        }

        if !self.args.output.quiet {
            println!("{}", MassScanner::generate_summary(&filtered_results));
        }

        // Export if requested (use filtered results)
        let exporter = ScanExporter::new(&self.args);
        if let Some(json_file) = exporter.collection_json_output_path() {
            use serde_json::json;

            let json_results: Vec<_> = filtered_results
                .iter()
                .map(|(target, result)| {
                    json!({
                        "target": target,
                        "success": result.is_ok(),
                        "results": result.as_ref().ok(),
                        "error": result.as_ref().err().map(|e| e.to_string()),
                    })
                })
                .collect();

            let json_data = json!({
                "scan_type": "mass_scan",
                "total_targets": filtered_results.len(),
                "successful_scans": filtered_results.iter().filter(|(_, r)| r.is_ok()).count(),
                "failed_scans": filtered_results.iter().filter(|(_, r)| r.is_err()).count(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "results": json_results,
            });

            let json = if self.args.output.json_pretty {
                serde_json::to_string_pretty(&json_data)?
            } else {
                serde_json::to_string(&json_data)?
            };
            exporter.write_text_file(&json_file, &json, "JSON", ExportKind::Json)?;
        }

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "MassScanCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mass_scan_command_name() {
        let cmd = MassScanCommand::new(Args::default());
        assert_eq!(cmd.name(), "MassScanCommand");
    }

    #[tokio::test]
    async fn test_mass_scan_requires_input_file() {
        let args = Args::default();
        let cmd = MassScanCommand::new(args);
        let err = cmd.execute().await.unwrap_err();
        assert!(format!("{err}").contains("Input file is required"));
    }
}
