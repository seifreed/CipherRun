// DatabaseCommand - Database operations (init, migrate, cleanup, history)
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
use crate::{Args, Result};
use async_trait::async_trait;

/// DatabaseCommand handles database operations
///
/// This command is responsible for:
/// - Initializing the database (--db-init)
/// - Cleaning up old scans (--cleanup-days)
/// - Querying scan history (--history)
pub struct DatabaseCommand {
    args: Args,
}

impl DatabaseCommand {
    /// Create a new DatabaseCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

#[async_trait]
impl Command for DatabaseCommand {
    async fn execute(&self) -> Result<()> {
        use crate::db::CipherRunDatabase;

        let db_config_path = self
            .args
            .database
            .config
            .as_ref()
            .map(|p| p.to_str().unwrap_or("database.toml"))
            .unwrap_or("database.toml");

        let db = CipherRunDatabase::from_config_file(db_config_path).await?;

        // Initialize database
        if self.args.database.init {
            println!("✓ Database initialized successfully");
        }

        // Cleanup old scans
        if let Some(days) = self.args.database.cleanup_days {
            let deleted = db.cleanup_old_scans(days).await?;
            println!(
                "✓ Deleted {} old scan(s) (older than {} days)",
                deleted, days
            );
        }

        // Query scan history
        if let Some(history_target) = &self.args.database.history {
            let parts: Vec<&str> = history_target.split(':').collect();
            let hostname = parts.first().unwrap_or(&"").to_string();
            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

            let scans = db
                .get_scan_history(&hostname, port, self.args.database.history_limit)
                .await?;

            println!("\nScan History for {}:{}", hostname, port);
            println!("{}", "=".repeat(80));

            if scans.is_empty() {
                println!("No scan history found");
            } else {
                for scan in scans {
                    println!(
                        "  {} - Grade: {} | Score: {} | Duration: {}ms",
                        scan.scan_timestamp.format("%Y-%m-%d %H:%M:%S"),
                        scan.overall_grade.as_deref().unwrap_or("N/A"),
                        scan.overall_score.unwrap_or(0),
                        scan.scan_duration_ms.unwrap_or(0)
                    );
                }
            }
        }

        db.close().await;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "DatabaseCommand"
    }
}
