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

pub use command::Command;
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
