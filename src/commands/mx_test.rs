// MxTestCommand - MX record testing for mail servers
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
use crate::{Args, Result, TlsError};
use async_trait::async_trait;

/// MxTestCommand handles MX record testing for mail servers
///
/// This command is responsible for:
/// - Resolving MX records for a domain
/// - Scanning all MX servers
/// - Generating summary reports
/// - Exporting results to JSON if requested
pub struct MxTestCommand {
    args: Args,
}

impl MxTestCommand {
    /// Create a new MxTestCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

#[async_trait]
impl Command for MxTestCommand {
    async fn execute(&self) -> Result<()> {
        use crate::utils::mx::MxTester;

        let mx_domain = self
            .args
            .mx_domain
            .as_ref()
            .ok_or_else(|| TlsError::InvalidInput {
                message: "MX domain is required".to_string(),
            })?;

        let mx_tester = MxTester::new(mx_domain.clone());
        let results = mx_tester.scan_all_mx(self.args.clone()).await?;

        // Display summary
        println!("{}", MxTester::generate_mx_summary(&results));

        // Export if requested
        if let Some(json_file) = &self.args.output.json {
            use serde_json::json;
            let json_data = json!({
                "scan_type": "mx_records",
                "domain": mx_domain,
                "total_mx_servers": results.len(),
                "results": results.iter().map(|(mx, result)| {
                    json!({
                        "priority": mx.priority,
                        "hostname": mx.hostname,
                        "success": result.is_ok(),
                        "scan_results": result.as_ref().ok(),
                        "error": result.as_ref().err().map(|e| e.to_string()),
                    })
                }).collect::<Vec<_>>(),
            });

            let json_string = if self.args.output.json_pretty {
                serde_json::to_string_pretty(&json_data)?
            } else {
                serde_json::to_string(&json_data)?
            };

            std::fs::write(json_file, json_string)?;
            println!("✓ Results exported to JSON: {}", json_file.display());
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "MxTestCommand"
    }
}
