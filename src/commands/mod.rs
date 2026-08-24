// Commands module - Command Pattern implementation
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

mod command;
pub mod contract;
mod router;

// Individual command implementations
mod analytics;
mod anycast_scan;
mod api_server;
mod ct_logs;
mod database;
mod mass_scan;
mod monitor;
mod mx_test;
mod pqc_scan;
mod remediation;
mod scan;
mod scan_diff;
mod scan_exporter;
mod scan_notice_presenter;
mod scan_post_presenter;
mod scan_presenter;
mod scan_results_presenter;
mod schema;
mod worker;

pub use command::Command;
pub(crate) use command::exit_for_result_list;
pub use contract::CommandExit;
pub use router::CommandRouter;

// Re-export individual commands for testing purposes
pub use analytics::AnalyticsCommand;
pub use anycast_scan::AnycastScanCommand;
pub use api_server::ApiServerCommand;
pub use ct_logs::CtLogsCommand;
pub use database::DatabaseCommand;
pub use mass_scan::MassScanCommand;
pub use monitor::MonitorCommand;
pub use mx_test::MxTestCommand;
pub use pqc_scan::PqcScanCommand;
pub use remediation::RemediationCommand;
pub use scan::ScanCommand;
pub use scan_diff::ScanDiffCommand;
pub use schema::SchemaCommand;
pub use worker::WorkerCommand;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;

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
        assert_eq!(SchemaCommand::new(None).name(), "SchemaCommand");
        assert_eq!(
            RemediationCommand::new("input.json".into(), "nginx".to_string(), None, false).name(),
            "RemediationCommand"
        );
        assert_eq!(WorkerCommand::new(Args::default()).name(), "WorkerCommand");
    }
}
