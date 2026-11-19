// DatabaseCommand - Database operations (init, migrate, cleanup, history)
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{Command, CommandExit};
use crate::application::HostPortInput;
use crate::utils::network::canonical_target;
use crate::{Args, Result};
use async_trait::async_trait;
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info};

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
            .as_deref()
            .unwrap_or_else(|| Path::new("database.toml"));

        CipherRunDatabase::from_config_file(db_config_path).await
    }

    fn print_init_notice(&self) {
        if self.args.database.init {
            println!("✓ Database initialized successfully");
        }
    }

    async fn cleanup_old_scans(&self, db: &crate::db::CipherRunDatabase) -> Result<()> {
        if let Some(days) = self.args.database.cleanup_days {
            let started = Instant::now();
            let deleted = db.cleanup_old_scans(days).await?;
            log_cleanup_completed(
                days,
                deleted,
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
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

    fn format_optional<T: std::fmt::Display>(value: Option<T>) -> String {
        value
            .map(|value| value.to_string())
            .unwrap_or_else(|| "N/A".to_string())
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
                Self::format_optional(scan.overall_score),
                Self::format_optional(scan.scan_duration_ms)
            );
        }
    }

    async fn show_history(&self, db: &crate::db::CipherRunDatabase) -> Result<()> {
        if let Some(history_target) = &self.args.database.history {
            let (hostname, port) = self.parse_history_target(history_target)?;
            let started = Instant::now();
            let scans = db
                .get_scan_history(&hostname, port, self.args.database.history_limit)
                .await?;
            log_history_query_completed(
                port,
                self.args.database.history_limit,
                scans.len(),
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
            self.render_history(&hostname, port, &scans);
        }

        Ok(())
    }
}

fn log_cleanup_completed(days: i64, deleted_count: u64, duration_ms: u64) {
    info!(
        event_name = "database.cleanup.completed",
        operation = "cleanup_old_scans",
        days,
        deleted_count,
        duration_ms,
        outcome = "success",
        "Old scan cleanup completed"
    );
}

fn log_history_query_completed(port: u16, limit: i64, result_count: usize, duration_ms: u64) {
    debug!(
        event_name = "database.history.query.completed",
        operation = "get_scan_history",
        port,
        limit,
        result_count,
        duration_ms,
        outcome = "success",
        "Scan history query completed"
    );
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
    use crate::db::{CipherRunDatabase, Config, DatabaseConfig};
    #[cfg(unix)]
    use std::ffi::OsString;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedOutputWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedOutputWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedOutputWriter(self.0.clone())
        }
    }

    impl Write for CapturedOutputWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_database_command_name() {
        let args = Args::default();
        let cmd = DatabaseCommand::new(args);
        assert_eq!(cmd.name(), "DatabaseCommand");
    }

    fn write_sqlite_config(directory: &tempfile::TempDir) -> std::path::PathBuf {
        let config_path = directory.path().join("database.toml");
        let config = Config {
            database: DatabaseConfig::sqlite(directory.path().join("scans.sqlite")),
            retention: None,
        };
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        config_path
    }

    #[tokio::test]
    async fn database_command_runs_cleanup_and_history_for_a_configured_database() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = write_sqlite_config(&directory);
        let config = DatabaseConfig::sqlite(directory.path().join("scans.sqlite"));
        let db = CipherRunDatabase::new(&config).await.unwrap();
        crate::db::analytics::test_support::insert_scan(
            &db,
            "example.com",
            443,
            chrono::Utc::now(),
            Some("A"),
            Some(95),
        )
        .await;
        db.close().await;

        let mut args = Args::default();
        args.database.config = Some(config_path);
        args.database.init = true;
        args.database.cleanup_days = Some(30);
        args.database.history = Some("example.com:443".to_string());
        args.database.history_limit = 10;

        DatabaseCommand::new(args)
            .execute()
            .await
            .expect("database operations should succeed");
    }

    #[tokio::test]
    async fn database_command_accepts_empty_history_and_skips_optional_operations() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = write_sqlite_config(&directory);
        let mut args = Args::default();
        args.database.config = Some(config_path);
        args.database.history = Some("no-history.example".to_string());
        args.database.history_limit = 10;

        DatabaseCommand::new(args)
            .execute()
            .await
            .expect("empty history should succeed");
    }

    #[tokio::test]
    async fn database_command_rejects_invalid_history_target() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = write_sqlite_config(&directory);
        let mut args = Args::default();
        args.database.config = Some(config_path);
        args.database.history = Some("invalid host:443:extra".to_string());
        args.database.history_limit = 10;

        let error = DatabaseCommand::new(args)
            .execute()
            .await
            .expect_err("invalid history target should fail");

        assert!(error.to_string().contains("Invalid"));
    }

    #[test]
    fn test_database_history_formats_missing_numbers_as_unknown() {
        assert_eq!(DatabaseCommand::format_optional::<i32>(None), "N/A");
        assert_eq!(DatabaseCommand::format_optional::<i64>(None), "N/A");
        assert_eq!(DatabaseCommand::format_optional(Some(90)), "90");
        assert_eq!(DatabaseCommand::format_optional(Some(1200)), "1200");
    }

    #[test]
    fn database_operation_events_include_safe_structured_outcomes() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_cleanup_completed(30, 12, 27);
            log_history_query_completed(443, 10, 3, 8);
        });

        let output = output.0.lock().unwrap();
        let events: Vec<serde_json::Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("event should be JSON"))
            .collect();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["level"], "INFO");
        assert_eq!(
            events[0]["fields"]["event_name"],
            "database.cleanup.completed"
        );
        assert_eq!(events[0]["fields"]["deleted_count"], 12);
        assert_eq!(events[0]["fields"]["duration_ms"], 27);
        assert_eq!(events[0]["fields"]["outcome"], "success");
        assert_eq!(events[1]["level"], "DEBUG");
        assert_eq!(
            events[1]["fields"]["event_name"],
            "database.history.query.completed"
        );
        assert_eq!(events[1]["fields"]["result_count"], 3);
        assert_eq!(events[1]["fields"]["duration_ms"], 8);
        assert_eq!(events[1]["fields"]["outcome"], "success");
        assert!(!String::from_utf8_lossy(&output).contains("example.com"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_database_does_not_pre_reject_non_utf8_config_path() {
        let mut args = Args::default();
        args.database.config = Some(PathBuf::from(OsString::from_vec(vec![0x66, 0x80])));

        let cmd = DatabaseCommand::new(args);
        let err = match cmd.open_database().await {
            Ok(_) => panic!("non-UTF-8 config path should fail"),
            Err(err) => err,
        };

        assert!(!err.to_string().contains("invalid UTF-8"));
    }
}
