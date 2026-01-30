// AnalyticsCommand - Database analytics operations
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
use crate::{Args, Result, TlsError};
use async_trait::async_trait;

/// AnalyticsCommand handles database analytics operations
///
/// This command is responsible for:
/// - Comparing two scans (--compare)
/// - Detecting changes over time (--changes)
/// - Analyzing trends (--trends)
/// - Generating dashboard data (--dashboard)
pub struct AnalyticsCommand {
    args: Args,
}

impl AnalyticsCommand {
    /// Create a new AnalyticsCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

#[async_trait]
impl Command for AnalyticsCommand {
    async fn execute(&self) -> Result<()> {
        use crate::db::CipherRunDatabase;
        use crate::db::analytics::{
            ChangeTracker, DashboardGenerator, ScanComparator, TrendAnalyzer,
        };
        use std::sync::Arc;

        let db_config_path = self
            .args
            .database
            .config
            .as_ref()
            .map(|p| p.to_str().unwrap_or("database.toml"))
            .unwrap_or("database.toml");

        let db = Arc::new(CipherRunDatabase::from_config_file(db_config_path).await?);

        // Handle --compare
        if let Some(compare_str) = &self.args.compare {
            let parts: Vec<&str> = compare_str.split(':').collect();
            if parts.len() != 2 {
                eprintln!("Error: --compare requires format SCAN_ID_1:SCAN_ID_2");
                return Ok(());
            }

            let scan_id_1: i64 = parts[0].parse().map_err(|_| TlsError::InvalidInput {
                message: format!("Invalid scan ID: {}", parts[0]),
            })?;
            let scan_id_2: i64 = parts[1].parse().map_err(|_| TlsError::InvalidInput {
                message: format!("Invalid scan ID: {}", parts[1]),
            })?;

            let comparator = ScanComparator::new(db.clone());
            let comparison = comparator.compare_scans(scan_id_1, scan_id_2).await?;

            // Output format: JSON if --json flag is set, otherwise terminal
            let format = if self.args.output.json.is_some() || self.args.output.json_pretty {
                "json"
            } else {
                "terminal"
            };

            let output = comparator.format_comparison(&comparison, format)?;

            if let Some(json_path) = &self.args.output.json {
                std::fs::write(json_path, &output)?;
                println!("✓ Comparison saved to: {}", json_path.display());
            } else {
                println!("{}", output);
            }
        }

        // Handle --changes
        if let Some(changes_str) = &self.args.changes {
            let parts: Vec<&str> = changes_str.split(':').collect();
            if parts.len() != 3 {
                eprintln!("Error: --changes requires format HOSTNAME:PORT:DAYS");
                return Ok(());
            }

            let hostname = parts[0].to_string();
            let port: u16 = parts[1]
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port: {}", parts[1]))?;
            let days: i64 = parts[2]
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid days: {}", parts[2]))?;

            let tracker = ChangeTracker::new(db.clone());
            let changes = tracker.detect_changes(&hostname, port, days).await?;

            if self.args.output.json.is_some() || self.args.output.json_pretty {
                let json = if self.args.output.json_pretty {
                    serde_json::to_string_pretty(&changes)?
                } else {
                    serde_json::to_string(&changes)?
                };

                if let Some(json_path) = &self.args.output.json {
                    std::fs::write(json_path, &json)?;
                    println!("✓ Changes saved to: {}", json_path.display());
                } else {
                    println!("{}", json);
                }
            } else {
                let report = tracker.generate_change_report(&changes);
                println!("{}", report);
            }
        }

        // Handle --trends
        if let Some(trends_str) = &self.args.trends {
            let parts: Vec<&str> = trends_str.split(':').collect();
            if parts.len() != 3 {
                eprintln!("Error: --trends requires format HOSTNAME:PORT:DAYS");
                return Ok(());
            }

            let hostname = parts[0].to_string();
            let port: u16 = parts[1].parse().map_err(|_| TlsError::InvalidInput {
                message: format!("Invalid port: {}", parts[1]),
            })?;
            let days: i64 = parts[2].parse().map_err(|_| TlsError::InvalidInput {
                message: format!("Invalid days: {}", parts[2]),
            })?;

            let analyzer = TrendAnalyzer::new(db.clone());

            if self.args.output.json.is_some() || self.args.output.json_pretty {
                // Generate all trends and output as JSON
                let rating_trend = analyzer.analyze_rating_trend(&hostname, port, days).await?;
                let vuln_trend = analyzer
                    .analyze_vulnerability_trend(&hostname, port, days)
                    .await?;
                let protocol_trend = analyzer
                    .analyze_protocol_trend(&hostname, port, days)
                    .await?;

                let trends = serde_json::json!({
                    "rating_trend": rating_trend,
                    "vulnerability_trend": vuln_trend,
                    "protocol_trend": protocol_trend,
                });

                let json = if self.args.output.json_pretty {
                    serde_json::to_string_pretty(&trends)?
                } else {
                    serde_json::to_string(&trends)?
                };

                if let Some(json_path) = &self.args.output.json {
                    std::fs::write(json_path, &json)?;
                    println!("✓ Trends saved to: {}", json_path.display());
                } else {
                    println!("{}", json);
                }
            } else {
                let report = analyzer
                    .generate_trend_report(&hostname, port, days)
                    .await?;
                println!("{}", report);
            }
        }

        // Handle --dashboard
        if let Some(dashboard_str) = &self.args.dashboard {
            let parts: Vec<&str> = dashboard_str.split(':').collect();
            if parts.len() != 3 {
                eprintln!("Error: --dashboard requires format HOSTNAME:PORT:DAYS");
                return Ok(());
            }

            let hostname = parts[0].to_string();
            let port: u16 = parts[1].parse().map_err(|_| TlsError::InvalidInput {
                message: format!("Invalid port: {}", parts[1]),
            })?;
            let days: i64 = parts[2].parse().map_err(|_| TlsError::InvalidInput {
                message: format!("Invalid days: {}", parts[2]),
            })?;

            let generator = DashboardGenerator::new(db.clone());
            let dashboard = generator.generate_dashboard(&hostname, port, days).await?;

            let json = generator.to_json(&dashboard, self.args.output.json_pretty)?;

            if let Some(json_path) = &self.args.output.json {
                std::fs::write(json_path, &json)?;
                println!("✓ Dashboard data saved to: {}", json_path.display());
            } else {
                println!("{}", json);
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "AnalyticsCommand"
    }
}
