// AnalyticsCommand - Database analytics operations
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::scan_exporter::{ExportKind, ScanExporter};
use super::{Command, CommandExit};
use crate::application::{CompareScanIds, HostPortDaysInput};
use crate::{Args, Result};
use async_trait::async_trait;
use std::path::Path;

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

    async fn open_database(&self) -> Result<std::sync::Arc<crate::db::CipherRunDatabase>> {
        use crate::db::CipherRunDatabase;
        use std::sync::Arc;

        let db_config_path = self
            .args
            .database
            .config
            .as_deref()
            .unwrap_or_else(|| Path::new("database.toml"));

        Ok(Arc::new(
            CipherRunDatabase::from_config_file(db_config_path).await?,
        ))
    }

    fn parse_compare_ids(&self, raw: &str) -> Result<(i64, i64)> {
        let parsed = CompareScanIds::parse(raw)?;
        Ok((parsed.left, parsed.right))
    }

    fn parse_host_port_days(&self, raw: &str, _flag_name: &str) -> Result<HostPortDaysInput> {
        HostPortDaysInput::parse(raw)
    }

    fn prefers_json_output(&self) -> bool {
        self.args.output.json.is_some()
            || self.args.output.output_all.is_some()
            || self.args.output.json_pretty
    }

    fn print_or_save_output(&self, output: &str, _success_message: &str) -> Result<()> {
        let exporter = ScanExporter::new(&self.args);
        if let Some(json_path) = exporter.collection_json_output_path()? {
            exporter.write_text_file(&json_path, output, "JSON", ExportKind::Json)?;
        } else {
            println!("{}", output);
        }

        Ok(())
    }

    fn to_json<T: serde::Serialize>(&self, value: &T) -> Result<String> {
        if self.args.output.json_pretty {
            Ok(serde_json::to_string_pretty(value)?)
        } else {
            Ok(serde_json::to_string(value)?)
        }
    }

    async fn handle_compare(&self, compare_str: &str) -> Result<CommandExit> {
        use crate::db::analytics::ScanComparator;

        let (scan_id_1, scan_id_2) = self.parse_compare_ids(compare_str)?;

        let db = self.open_database().await?;
        let comparator = ScanComparator::new(db);
        let comparison = comparator.compare_scans(scan_id_1, scan_id_2).await?;
        let format = if self.prefers_json_output() {
            "json"
        } else {
            "terminal"
        };
        let output = comparator.format_comparison(&comparison, format)?;

        self.print_or_save_output(&output, "Comparison saved to:")?;
        Ok(CommandExit::success())
    }

    async fn handle_changes(&self, changes_str: &str) -> Result<CommandExit> {
        use crate::db::analytics::ChangeTracker;

        let input = self.parse_host_port_days(changes_str, "changes")?;

        let db = self.open_database().await?;
        let tracker = ChangeTracker::new(db);
        let changes = tracker
            .detect_changes(&input.hostname, input.port, input.days)
            .await?;

        if self.prefers_json_output() {
            let json = self.to_json(&changes)?;
            self.print_or_save_output(&json, "Changes saved to:")?;
        } else {
            let report = tracker.generate_change_report(&changes);
            println!("{}", report);
        }

        Ok(CommandExit::success())
    }

    async fn handle_trends(&self, trends_str: &str) -> Result<CommandExit> {
        use crate::db::analytics::TrendAnalyzer;

        let input = self.parse_host_port_days(trends_str, "trends")?;

        let db = self.open_database().await?;
        let analyzer = TrendAnalyzer::new(db);

        if self.prefers_json_output() {
            let rating_trend = analyzer
                .analyze_rating_trend(&input.hostname, input.port, input.days)
                .await?;
            let vuln_trend = analyzer
                .analyze_vulnerability_trend(&input.hostname, input.port, input.days)
                .await?;
            let protocol_trend = analyzer
                .analyze_protocol_trend(&input.hostname, input.port, input.days)
                .await?;

            let trends = serde_json::json!({
                "rating_trend": rating_trend,
                "vulnerability_trend": vuln_trend,
                "protocol_trend": protocol_trend,
            });

            let json = self.to_json(&trends)?;
            self.print_or_save_output(&json, "Trends saved to:")?;
        } else {
            let report = analyzer
                .generate_trend_report(&input.hostname, input.port, input.days)
                .await?;
            println!("{}", report);
        }

        Ok(CommandExit::success())
    }

    async fn handle_dashboard(&self, dashboard_str: &str) -> Result<CommandExit> {
        use crate::db::analytics::DashboardGenerator;

        let input = self.parse_host_port_days(dashboard_str, "dashboard")?;

        let db = self.open_database().await?;
        let generator = DashboardGenerator::new(db);
        let dashboard = generator
            .generate_dashboard(&input.hostname, input.port, input.days)
            .await?;
        let json = generator.to_json(&dashboard, self.args.output.json_pretty)?;
        self.print_or_save_output(&json, "Dashboard data saved to:")?;

        Ok(CommandExit::success())
    }
}

#[async_trait]
impl Command for AnalyticsCommand {
    async fn execute(&self) -> Result<CommandExit> {
        if let Some(compare_str) = &self.args.compare {
            return self.handle_compare(compare_str).await;
        }

        if let Some(changes_str) = &self.args.changes {
            return self.handle_changes(changes_str).await;
        }

        if let Some(trends_str) = &self.args.trends {
            return self.handle_trends(trends_str).await;
        }

        if let Some(dashboard_str) = &self.args.dashboard {
            return self.handle_dashboard(dashboard_str).await;
        }

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "AnalyticsCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_analytics_command_name() {
        let args = Args {
            compare: None,
            ..Default::default()
        };
        let cmd = AnalyticsCommand::new(args);
        assert_eq!(cmd.name(), "AnalyticsCommand");
    }

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn create_temp_db_config() -> PathBuf {
        let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        #[cfg(unix)]
        let db_path = PathBuf::from(format!("/tmp/cipherrun-analytics-test{}.db", counter));
        #[cfg(not(unix))]
        let db_path = std::env::temp_dir().join(format!("cipherrun-analytics-test{}.db", counter));
        let _ = std::fs::remove_file(&db_path);

        let config_path = {
            #[cfg(unix)]
            {
                PathBuf::from(format!("/tmp/cipherrun-analytics-test{}.toml", counter))
            }
            #[cfg(not(unix))]
            {
                std::env::temp_dir().join(format!("cipherrun-analytics-test{}.toml", counter))
            }
        };

        let config = format!(
            "[database]\n\
type = \"sqlite\"\n\
path = \"{}\"\n",
            db_path.display()
        );
        std::fs::write(&config_path, config).expect("test assertion should succeed");
        config_path
    }

    #[tokio::test]
    async fn test_analytics_compare_invalid_format() {
        let mut args = Args::default();
        args.database.config = Some(create_temp_db_config());
        args.compare = Some("only-one-id".to_string());

        let cmd = AnalyticsCommand::new(args);
        let err = cmd
            .execute()
            .await
            .expect_err("invalid compare format should fail");
        assert!(err.to_string().contains("SCAN_ID_1:SCAN_ID_2"));
    }

    #[tokio::test]
    async fn test_analytics_changes_invalid_format() {
        let mut args = Args::default();
        args.database.config = Some(create_temp_db_config());
        args.changes = Some("missing:parts".to_string());

        let cmd = AnalyticsCommand::new(args);
        let err = cmd
            .execute()
            .await
            .expect_err("invalid changes format should fail");
        assert!(err.to_string().contains("HOSTNAME:PORT:DAYS"));
    }

    #[tokio::test]
    async fn test_analytics_dashboard_invalid_format() {
        let mut args = Args::default();
        args.database.config = Some(create_temp_db_config());
        args.dashboard = Some("missing:parts".to_string());

        let cmd = AnalyticsCommand::new(args);
        let err = cmd
            .execute()
            .await
            .expect_err("invalid dashboard format should fail");
        assert!(err.to_string().contains("HOSTNAME:PORT:DAYS"));
    }

    #[tokio::test]
    async fn test_analytics_trends_invalid_port() {
        let mut args = Args::default();
        args.database.config = Some(create_temp_db_config());
        args.trends = Some("example.com:notaport:7".to_string());

        let cmd = AnalyticsCommand::new(args);
        assert!(cmd.execute().await.is_err());
    }

    #[test]
    fn test_analytics_json_output_uses_export_guards() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("analytics.json");
        std::fs::write(&path, "{}").expect("seed file should be written");

        let args = Args {
            output: crate::cli::OutputArgs {
                json: Some(path),
                ..Default::default()
            },
            ..Default::default()
        };
        let cmd = AnalyticsCommand::new(args);
        let err = cmd
            .print_or_save_output("{}", "saved to:")
            .expect_err("existing output should be protected");

        assert!(err.to_string().contains("Refusing to overwrite"));
    }

    #[test]
    fn test_analytics_json_output_uses_output_all_and_outprefix() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let args = Args {
            output: crate::cli::OutputArgs {
                output_all: Some(dir.path().join("analytics")),
                outprefix: Some("pref-".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let cmd = AnalyticsCommand::new(args);
        cmd.print_or_save_output("{\"ok\":true}", "saved to:")
            .expect("output should be written");

        let path = dir.path().join("pref-analytics.json");
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_analytics_does_not_pre_reject_non_utf8_database_config_path() {
        let mut args = Args::default();
        args.database.config = Some(PathBuf::from(OsString::from_vec(vec![0x66, 0x80])));

        let cmd = AnalyticsCommand::new(args);
        let err = match cmd.open_database().await {
            Ok(_) => panic!("non-UTF-8 config path should fail"),
            Err(err) => err,
        };

        assert!(!err.to_string().contains("invalid UTF-8"));
    }
}
