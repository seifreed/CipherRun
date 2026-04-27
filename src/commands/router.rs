// CommandRouter - Routes CLI arguments to appropriate Command
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{
    AnalyticsCommand, ApiServerCommand, Command, CtLogsCommand, DatabaseCommand, MassScanCommand,
    MonitorCommand, MxTestCommand, PqcScanCommand, ScanCommand,
};
use crate::cli::CipherRunSubcommand;
use crate::{Args, Result, TlsError};

/// CommandRouter determines which Command to execute based on CLI arguments
///
/// This router follows a priority-based routing strategy:
/// 1. API server mode (--serve)
/// 2. Monitoring operations (--monitor, --test-alert)
/// 3. Database operations (--db-init, --cleanup-days, --history)
/// 4. Analytics operations (--compare, --changes, --trends, --dashboard)
/// 5. CT logs streaming (--ct-logs)
/// 6. MX record testing (--mx)
/// 7. Mass scanning (--file)
/// 8. Single target scanning (default)
///
/// # Design Principles
/// - Single Responsibility: Routes to one command based on arguments
/// - Open/Closed: New routing rules can be added without modifying existing logic
/// - Liskov Substitution: All commands conform to the Command trait
/// - Dependency Inversion: Router depends on Command abstraction, not concrete types
pub struct CommandRouter;

impl CommandRouter {
    fn has_routable_action(args: &Args) -> bool {
        args.subcommand.is_some()
            || args.api_server.enable
            || args.monitoring.enable
            || args.monitoring.test_alert
            || args.ct_logs.enable
            || args.compare.is_some()
            || args.changes.is_some()
            || args.trends.is_some()
            || args.dashboard.is_some()
            || args.database.init
            || args.database.cleanup_days.is_some()
            || args.database.history.is_some()
            || args.mx_domain.is_some()
            || args.input_file.is_some()
            || args.target.is_some()
    }

    /// Route CLI arguments to the appropriate Command
    ///
    /// # Arguments
    /// * `args` - Parsed command-line arguments
    ///
    /// # Returns
    /// A boxed Command trait object ready for execution
    ///
    /// # Routing Logic
    /// The router checks flags in order of priority and returns the first matching command:
    /// - If no specific mode is detected but a target is present, defaults to ScanCommand
    /// - Multiple modes can be active (e.g., database + scanning), router handles precedence
    ///
    /// # Errors
    /// Returns a TlsError if invalid argument combinations are detected
    pub fn route(args: Args) -> Result<Box<dyn Command>> {
        Self::validate_routing(&args)?;

        // Priority 0: Subcommands
        if let Some(CipherRunSubcommand::Pqc { ssh, vpn, code }) = args.subcommand.clone() {
            return Ok(Box::new(PqcScanCommand::new(ssh, vpn, code)));
        }

        // Priority 1: API server mode
        if args.api_server.enable {
            return Ok(Box::new(ApiServerCommand::new(args)));
        }

        // Priority 2: Monitoring operations
        if args.monitoring.enable || args.monitoring.test_alert {
            return Ok(Box::new(MonitorCommand::new(args)));
        }

        // Priority 3: CT logs streaming
        if args.ct_logs.enable {
            return Ok(Box::new(CtLogsCommand::new(args)));
        }

        // Priority 4: Analytics operations
        if args.compare.is_some()
            || args.changes.is_some()
            || args.trends.is_some()
            || args.dashboard.is_some()
        {
            return Ok(Box::new(AnalyticsCommand::new(args)));
        }

        // Priority 5: Database-only operations (without scanning)
        // Check if database operations are requested WITHOUT a target
        if (args.database.init
            || args.database.cleanup_days.is_some()
            || args.database.history.is_some())
            && args.target.is_none()
            && args.input_file.is_none()
            && args.mx_domain.is_none()
        {
            return Ok(Box::new(DatabaseCommand::new(args)));
        }

        // Priority 6: MX record testing
        if args.mx_domain.is_some() {
            return Ok(Box::new(MxTestCommand::new(args)));
        }

        // Priority 7: Mass scanning from file
        if args.input_file.is_some() {
            return Ok(Box::new(MassScanCommand::new(args)));
        }

        // Priority 8: Single target scanning (default)
        // This handles both explicit targets and database operations with scanning
        Ok(Box::new(ScanCommand::new(args)))
    }

    /// Check if the given arguments represent a valid command configuration
    ///
    /// This validates that the argument combination makes sense and can be routed
    ///
    /// # Returns
    /// - `Ok(())` if the arguments are valid
    /// - `Err(TlsError)` with description if invalid
    pub fn validate_routing(args: &Args) -> Result<()> {
        // Check for conflicting operational modes
        let mode_count = [
            args.subcommand.is_some(),
            args.api_server.enable,
            args.monitoring.enable || args.monitoring.test_alert,
            args.ct_logs.enable,
            args.compare.is_some()
                || args.changes.is_some()
                || args.trends.is_some()
                || args.dashboard.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        if mode_count > 1 {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine multiple operational modes (--serve, --monitor, --ct-logs, analytics)".to_string(),
            });
        }

        let exclusive_mode_active = mode_count == 1;
        let additional_action_requested = args.target.is_some()
            || args.input_file.is_some()
            || args.mx_domain.is_some()
            || args.database.init
            || args.database.cleanup_days.is_some()
            || args.database.history.is_some();

        if exclusive_mode_active && additional_action_requested {
            return Err(TlsError::InvalidInput {
                message: "Operational modes (--serve, --monitor, --ct-logs, analytics) cannot be combined with scan targets, MX/file input, or database action flags.".to_string(),
            });
        }

        // Check for MX + file conflict
        if args.mx_domain.is_some() && args.input_file.is_some() {
            return Err(TlsError::InvalidInput {
                message: "Cannot use --mx with --file. Choose one scanning mode.".to_string(),
            });
        }

        // Check for target + file conflict
        if args.target.is_some() && args.input_file.is_some() {
            return Err(TlsError::InvalidInput {
                message: "Cannot specify both target and --file. Choose one scanning mode."
                    .to_string(),
            });
        }

        if !Self::has_routable_action(args) {
            return Err(TlsError::InvalidInput {
                message: "No target or operational mode specified.".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{ApiServerArgs, CtLogsArgs, DatabaseArgs, MonitoringArgs};

    #[test]
    fn test_route_pqc_subcommand() {
        let args = Args {
            subcommand: Some(crate::cli::CipherRunSubcommand::Pqc {
                ssh: None,
                vpn: None,
                code: None,
            }),
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "PqcScanCommand");
    }

    #[test]
    fn test_route_api_server() {
        let args = Args {
            api_server: ApiServerArgs {
                enable: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "ApiServerCommand");
    }

    #[test]
    fn test_route_monitor() {
        let args = Args {
            monitoring: MonitoringArgs {
                enable: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "MonitorCommand");
    }

    #[test]
    fn test_route_ct_logs() {
        let args = Args {
            ct_logs: CtLogsArgs {
                enable: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "CtLogsCommand");
    }

    #[test]
    fn test_route_analytics() {
        let args = Args {
            compare: Some("1:2".to_string()),
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "AnalyticsCommand");
    }

    #[test]
    fn test_route_database() {
        let args = Args {
            database: DatabaseArgs {
                init: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "DatabaseCommand");
    }

    #[test]
    fn test_route_mx_test() {
        let args = Args {
            mx_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "MxTestCommand");
    }

    #[test]
    fn test_route_mass_scan() {
        let args = Args {
            input_file: Some(std::path::PathBuf::from("targets.txt")),
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "MassScanCommand");
    }

    #[test]
    fn test_route_scan_target() {
        let args = Args {
            target: Some("example.com:443".to_string()),
            ..Default::default()
        };
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "ScanCommand");
    }

    #[test]
    fn test_validate_conflicting_modes() {
        let args = Args {
            api_server: ApiServerArgs {
                enable: true,
                ..Default::default()
            },
            monitoring: MonitoringArgs {
                enable: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = CommandRouter::validate_routing(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mx_file_conflict() {
        let args = Args {
            mx_domain: Some("example.com".to_string()),
            input_file: Some(std::path::PathBuf::from("targets.txt")),
            ..Default::default()
        };
        let result = CommandRouter::validate_routing(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_operational_mode_with_target_conflict() {
        let args = Args {
            api_server: ApiServerArgs {
                enable: true,
                ..Default::default()
            },
            target: Some("example.com:443".to_string()),
            ..Default::default()
        };
        let result = CommandRouter::validate_routing(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_requires_target_or_mode() {
        let result = CommandRouter::validate_routing(&Args::default());
        assert!(result.is_err());
    }
}
