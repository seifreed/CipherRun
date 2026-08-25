// Commands module - Command Pattern implementation
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

mod command;
pub mod contract;
mod router;

// Individual command implementations
mod analytics;
mod anycast_scan;
#[cfg(feature = "api")]
mod api_server;
#[cfg(not(feature = "api"))]
mod api_server_disabled {
    use super::{Command, CommandExit};
    use async_trait::async_trait;

    pub struct ApiServerCommand {
        args: crate::Args,
    }

    impl ApiServerCommand {
        pub fn new(args: crate::Args) -> Self {
            Self { args }
        }
    }

    #[async_trait]
    impl Command for ApiServerCommand {
        async fn execute(&self) -> crate::Result<CommandExit> {
            let _ = &self.args;
            Err(crate::TlsError::ConfigError {
                message: "API server support requires the `api` feature".to_string(),
            })
        }

        fn name(&self) -> &'static str {
            "ApiServerCommand"
        }
    }
}
#[cfg(feature = "ct")]
mod ct_logs;
mod database;
mod mass_scan;
#[cfg(feature = "monitoring")]
mod monitor;
mod mx_test;
#[cfg(feature = "pqc")]
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
#[cfg(feature = "api")]
pub use api_server::ApiServerCommand;
#[cfg(not(feature = "api"))]
pub use api_server_disabled::ApiServerCommand;
#[cfg(feature = "ct")]
pub use ct_logs::CtLogsCommand;
#[cfg(not(feature = "ct"))]
pub struct CtLogsCommand {
    args: crate::Args,
}

#[cfg(not(feature = "ct"))]
impl CtLogsCommand {
    pub fn new(args: crate::Args) -> Self {
        Self { args }
    }
}

#[cfg(not(feature = "ct"))]
#[async_trait::async_trait]
impl Command for CtLogsCommand {
    async fn execute(&self) -> crate::Result<CommandExit> {
        let _ = &self.args;
        Err(crate::TlsError::ConfigError {
            message: "CT log streaming requires the `ct` feature".to_string(),
        })
    }

    fn name(&self) -> &'static str {
        "CtLogsCommand"
    }
}
pub use database::DatabaseCommand;
pub use mass_scan::MassScanCommand;
#[cfg(feature = "monitoring")]
pub use monitor::MonitorCommand;
#[cfg(not(feature = "monitoring"))]
pub struct MonitorCommand {
    args: crate::Args,
}

#[cfg(not(feature = "monitoring"))]
impl MonitorCommand {
    pub fn new(args: crate::Args) -> Self {
        Self { args }
    }
}

#[cfg(not(feature = "monitoring"))]
#[async_trait::async_trait]
impl Command for MonitorCommand {
    async fn execute(&self) -> crate::Result<CommandExit> {
        let _ = &self.args;
        Err(crate::TlsError::ConfigError {
            message: "monitoring operations require the `monitoring` feature".to_string(),
        })
    }

    fn name(&self) -> &'static str {
        "MonitorCommand"
    }
}
pub use mx_test::MxTestCommand;
#[cfg(feature = "pqc")]
pub use pqc_scan::PqcScanCommand;
#[cfg(not(feature = "pqc"))]
pub struct PqcScanCommand {
    args: crate::Args,
}

#[cfg(not(feature = "pqc"))]
impl PqcScanCommand {
    pub fn new(
        _ssh_path: Option<std::path::PathBuf>,
        _vpn_path: Option<std::path::PathBuf>,
        _code_path: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            args: crate::Args::default(),
        }
    }
}

#[cfg(not(feature = "pqc"))]
#[async_trait::async_trait]
impl Command for PqcScanCommand {
    async fn execute(&self) -> crate::Result<CommandExit> {
        let _ = &self.args;
        Err(crate::TlsError::ConfigError {
            message: "PQC configuration scanners require the `pqc` feature".to_string(),
        })
    }

    fn name(&self) -> &'static str {
        "PqcScanCommand"
    }
}
pub use remediation::RemediationCommand;
pub use scan::ScanCommand;
pub use scan_diff::ScanDiffCommand;
pub use schema::SchemaCommand;
pub use worker::{WorkerCommand, run_worker};

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
