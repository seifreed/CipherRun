// DatabaseCommand - Database operations (init, migrate, cleanup, history)
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{Command, CommandExit};
use crate::application::HostPortInput;
use crate::utils::network::canonical_target;
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

    async fn open_database(&self) -> Result<crate::db::CipherRunDatabase> {
        use crate::db::CipherRunDatabase;

        let db_config_path = self
            .args
            .database
            .config
            .as_ref()
            .map(|p| p.to_str().unwrap_or("database.toml"))
            .unwrap_or("database.toml");

        CipherRunDatabase::from_config_file(db_config_path).await
    }

    fn print_init_notice(&self) {
        if self.args.database.init {
            println!("✓ Database initialized successfully");
        }
    }

    async fn cleanup_old_scans(&self, db: &crate::db::CipherRunDatabase) -> Result<()> {
        if let Some(days) = self.args.database.cleanup_days {
            let deleted = db.cleanup_old_scans(days).await?;
            println!(
                "✓ Deleted {} old scan(s) (older than {} days)",
                deleted, days
            );
        }

        Ok(())
    }

    fn parse_history_target(&self, history_target: &str) -> Result<(String, u16)> {
        let parsed = HostPortInput::parse_with_default_port(history_target, 443)?;
        Ok((parsed.hostname, parsed.port))
    }

    fn render_history(&self, hostname: &str, port: u16, scans: &[crate::db::models::ScanRecord]) {
        println!("\nScan History for {}", canonical_target(hostname, port));
        println!("{}", "=".repeat(80));

        if scans.is_empty() {
            println!("No scan history found");
            return;
        }

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

    async fn show_history(&self, db: &crate::db::CipherRunDatabase) -> Result<()> {
        if let Some(history_target) = &self.args.database.history {
            let (hostname, port) = self.parse_history_target(history_target)?;
            let scans = db
                .get_scan_history(&hostname, port, self.args.database.history_limit)
                .await?;
            self.render_history(&hostname, port, &scans);
        }

        Ok(())
    }
}

#[async_trait]
impl Command for DatabaseCommand {
    async fn execute(&self) -> Result<CommandExit> {
        let db = self.open_database().await?;
        self.print_init_notice();
        self.cleanup_old_scans(&db).await?;
        self.show_history(&db).await?;

        db.close().await;

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "DatabaseCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;

    #[test]
    fn test_database_command_name() {
        let args = Args::default();
        let cmd = DatabaseCommand::new(args);
        assert_eq!(cmd.name(), "DatabaseCommand");
    }
}
