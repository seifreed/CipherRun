// CommandRouter - Routes CLI arguments to appropriate Command
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{
    AnalyticsCommand, ApiServerCommand, Command, CtLogsCommand, DatabaseCommand, MassScanCommand,
    MonitorCommand, MxTestCommand, ScanCommand,
};
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
    /// - If no specific mode is detected, defaults to ScanCommand
    /// - Multiple modes can be active (e.g., database + scanning), router handles precedence
    ///
    /// # Errors
    /// Returns a TlsError if invalid argument combinations are detected
    pub fn route(args: Args) -> Result<Box<dyn Command>> {
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_api_server() {
        let mut args = Args::default();
        args.api_server.enable = true;
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "ApiServerCommand");
    }

    #[test]
    fn test_route_monitor() {
        let mut args = Args::default();
        args.monitoring.enable = true;
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "MonitorCommand");
    }

    #[test]
    fn test_route_ct_logs() {
        let mut args = Args::default();
        args.ct_logs.enable = true;
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "CtLogsCommand");
    }

    #[test]
    fn test_route_analytics() {
        let mut args = Args::default();
        args.compare = Some("1:2".to_string());
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "AnalyticsCommand");
    }

    #[test]
    fn test_route_database() {
        let mut args = Args::default();
        args.database.init = true;
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "DatabaseCommand");
    }

    #[test]
    fn test_route_mx_test() {
        let mut args = Args::default();
        args.mx_domain = Some("example.com".to_string());
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "MxTestCommand");
    }

    #[test]
    fn test_route_mass_scan() {
        let mut args = Args::default();
        args.input_file = Some(std::path::PathBuf::from("targets.txt"));
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "MassScanCommand");
    }

    #[test]
    fn test_route_scan_default() {
        let args = Args::default();
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), "ScanCommand");
    }

    #[test]
    fn test_validate_conflicting_modes() {
        let mut args = Args::default();
        args.api_server.enable = true;
        args.monitoring.enable = true;
        let result = CommandRouter::validate_routing(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mx_file_conflict() {
        let mut args = Args::default();
        args.mx_domain = Some("example.com".to_string());
        args.input_file = Some(std::path::PathBuf::from("targets.txt"));
        let result = CommandRouter::validate_routing(&args);
        assert!(result.is_err());
    }
}
