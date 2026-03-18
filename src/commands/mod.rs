// Commands module - Command Pattern implementation
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

mod command;
mod router;

// Individual command implementations
mod analytics;
mod api_server;
mod ct_logs;
mod database;
mod mass_scan;
mod monitor;
mod mx_test;
mod scan;
mod scan_exporter;
mod scan_notice_presenter;
mod scan_post_presenter;
mod scan_presenter;
mod scan_results_presenter;

pub use command::{Command, CommandExit};
pub use router::CommandRouter;

// Re-export individual commands for testing purposes
pub use analytics::AnalyticsCommand;
pub use api_server::ApiServerCommand;
pub use ct_logs::CtLogsCommand;
pub use database::DatabaseCommand;
pub use mass_scan::MassScanCommand;
pub use monitor::MonitorCommand;
pub use mx_test::MxTestCommand;
pub use scan::ScanCommand;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commands_reexports_names() {
        let args = crate::Args::default();
        assert_eq!(
            ApiServerCommand::new(args.clone()).name(),
            "ApiServerCommand"
        );
        assert_eq!(CtLogsCommand::new(args.clone()).name(), "CtLogsCommand");
        assert_eq!(DatabaseCommand::new(args.clone()).name(), "DatabaseCommand");
        assert_eq!(ScanCommand::new(args).name(), "ScanCommand");
    }
}
