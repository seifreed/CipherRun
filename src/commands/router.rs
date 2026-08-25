// CommandRouter - Routes CLI arguments to appropriate Command
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::MonitorCommand;
use super::{
    AnalyticsCommand, AnycastScanCommand, ApiServerCommand, Command, CtLogsCommand,
    DatabaseCommand, MassScanCommand, MxTestCommand, PqcScanCommand, RemediationCommand,
    ScanCommand, ScanDiffCommand, SchemaCommand, WorkerCommand,
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
/// 7. Mass scanning (--file, --asn, --cidr)
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
            || args.api_server.worker
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
            || args.asn.is_some()
            || args.cidr.is_some()
            || args.target.is_some()
    }

    fn has_output_artifact_options(args: &Args) -> bool {
        args.output.json.is_some()
            || args.output.json_multi_ip.is_some()
            || args.output.csv.is_some()
            || args.output.html.is_some()
            || args.output.xml.is_some()
            || args.output.sarif.is_some()
            || args.output.junit.is_some()
            || args.output.output_all.is_some()
            || args.output.outprefix.is_some()
            || args.output.json_pretty
            || args.output.append
            || args.output.overwrite
            || args.output.fail_on.is_some()
            || args.output.baseline.is_some()
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
        if let Some(CipherRunSubcommand::Diff {
            previous,
            current,
            json,
        }) = args.subcommand.clone()
        {
            return Ok(Box::new(ScanDiffCommand::new(previous, current, json)));
        }
        if let Some(CipherRunSubcommand::Schema { output }) = args.subcommand.clone() {
            return Ok(Box::new(SchemaCommand::new(output)));
        }
        if let Some(CipherRunSubcommand::Remediate {
            input,
            format,
            output,
            overwrite,
        }) = args.subcommand.clone()
        {
            return Ok(Box::new(RemediationCommand::new(
                input, format, output, overwrite,
            )));
        }

        // Priority 1: standalone worker or API server mode
        if args.api_server.worker {
            return Ok(Box::new(WorkerCommand::new(args)));
        }
        if args.api_server.enable {
            return Ok(Box::new(ApiServerCommand::new(args)));
        }

        // Priority 2: Monitoring operations
        if args.monitoring.enable || args.monitoring.test_alert {
            #[cfg(feature = "monitoring")]
            return Ok(Box::new(MonitorCommand::new(args)));
            #[cfg(not(feature = "monitoring"))]
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
        // Check if database operations are requested WITHOUT a scan source. All
        // scan sources must be excluded here (target, --file, --mx, --asn,
        // --cidr); otherwise a database flag would shadow the scan source and
        // silently drop the scan.
        if (args.database.init
            || args.database.cleanup_days.is_some()
            || args.database.history.is_some())
            && args.target.is_none()
            && args.input_file.is_none()
            && args.asn.is_none()
            && args.cidr.is_none()
            && args.mx_domain.is_none()
        {
            return Ok(Box::new(DatabaseCommand::new(args)));
        }

        // Priority 6: MX record testing
        if args.mx_domain.is_some() {
            return Ok(Box::new(MxTestCommand::new(args)));
        }

        // Priority 7: Mass scanning from a file or an expanded CIDR/ASN range
        if args.input_file.is_some() || args.asn.is_some() || args.cidr.is_some() {
            return Ok(Box::new(MassScanCommand::new(args)));
        }

        // Priority 7.5: Anycast scanning of all resolved IPs for a single target
        // (validated in Args::validate to require a single target).
        if args.network.scan_all_ips {
            return Ok(Box::new(AnycastScanCommand::new(args)));
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
        if args.api_server.enable && args.api_server.worker {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine --serve and --worker".to_string(),
            });
        }
        if args.api_server.worker {
            if args.api_server.config.is_none() {
                return Err(TlsError::InvalidInput {
                    message: "--worker requires --api-config".to_string(),
                });
            }
            if args.database.config.is_none() {
                return Err(TlsError::InvalidInput {
                    message: "--worker requires --db-config".to_string(),
                });
            }
        }

        // Check for conflicting operational modes
        let mode_count = [
            args.subcommand.is_some(),
            args.api_server.enable || args.api_server.worker,
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
                message: "Cannot combine multiple operational modes (--serve, --worker, --monitor, --ct-logs, analytics)".to_string(),
            });
        }

        let analytics_count = [
            args.compare.is_some(),
            args.changes.is_some(),
            args.trends.is_some(),
            args.dashboard.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();
        if analytics_count > 1 {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine multiple analytics operations (--compare, --changes, --trends, --dashboard). Choose one.".to_string(),
            });
        }
        if analytics_count == 1
            && (args.output.csv.is_some()
                || args.output.html.is_some()
                || args.output.xml.is_some()
                || args.output.sarif.is_some()
                || args.output.junit.is_some())
        {
            return Err(TlsError::InvalidInput {
                message: "Analytics output supports terminal or JSON only; CSV/HTML/XML/SARIF/JUnit exports are not available.".to_string(),
            });
        }
        if args.ct_logs.enable && args.ct_logs.beginning && !args.ct_logs.index.is_empty() {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine --ct-beginning with --ct-index. Choose one CT log start position.".to_string(),
            });
        }

        let exclusive_mode_active = mode_count == 1;
        let additional_action_requested = args.target.is_some()
            || args.input_file.is_some()
            || args.asn.is_some()
            || args.cidr.is_some()
            || args.mx_domain.is_some()
            || args.database.init
            || args.database.cleanup_days.is_some()
            || args.database.history.is_some();

        if exclusive_mode_active && additional_action_requested {
            return Err(TlsError::InvalidInput {
                message: "Operational modes (--serve, --monitor, --ct-logs, analytics) cannot be combined with scan targets, MX/file/ASN/CIDR input, or database action flags.".to_string(),
            });
        }
        if (args.subcommand.is_some()
            || args.api_server.enable
            || args.api_server.worker
            || args.monitoring.enable
            || args.monitoring.test_alert
            || args.ct_logs.enable)
            && Self::has_output_artifact_options(args)
        {
            return Err(TlsError::InvalidInput {
                message: "PQC/API/monitor/CT logs modes do not support scan output artifact options. Use mode-specific output flags such as --ct-json where available.".to_string(),
            });
        }

        // Mass-scan target sources (--file, --asn, --cidr) and a single target/MX
        // are mutually exclusive: each selects a distinct scanning mode.
        let mass_sources = [
            args.input_file.is_some(),
            args.asn.is_some(),
            args.cidr.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();
        if mass_sources > 1 {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine --file, --asn, and --cidr. Choose one mass-scan source."
                    .to_string(),
            });
        }

        let any_mass_source = mass_sources == 1;
        let database_action_requested = args.database.init
            || args.database.cleanup_days.is_some()
            || args.database.history.is_some();
        let scan_source_requested = args.target.is_some()
            || args.input_file.is_some()
            || args.asn.is_some()
            || args.cidr.is_some()
            || args.mx_domain.is_some();

        if database_action_requested && scan_source_requested {
            return Err(TlsError::InvalidInput {
                message: "Database actions (--db-init, --cleanup-days, --history) cannot be combined with scan targets, MX/file/ASN/CIDR input, or --mx. Use --store-results for scan persistence.".to_string(),
            });
        }
        if database_action_requested && Self::has_output_artifact_options(args) {
            return Err(TlsError::InvalidInput {
                message: "Database actions (--db-init, --cleanup-days, --history) do not support scan output artifact options.".to_string(),
            });
        }

        // Check for MX + mass-source conflict
        if args.mx_domain.is_some() && any_mass_source {
            return Err(TlsError::InvalidInput {
                message: "Cannot use --mx with --file/--asn/--cidr. Choose one scanning mode."
                    .to_string(),
            });
        }

        if args.mx_domain.is_some() && args.target.is_some() {
            return Err(TlsError::InvalidInput {
                message: "Cannot use --mx with a scan target. Choose one scanning mode."
                    .to_string(),
            });
        }

        // Check for target + mass-source conflict
        if args.target.is_some() && any_mass_source {
            return Err(TlsError::InvalidInput {
                message:
                    "Cannot specify both target and --file/--asn/--cidr. Choose one scanning mode."
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
    #[cfg(feature = "monitoring")]
    use crate::cli::CtLogsArgs;
    use crate::cli::{ApiServerArgs, DatabaseArgs, MonitoringArgs};

    fn assert_routes_to(args: Args, expected_name: &str) {
        let cmd = CommandRouter::route(args).expect("test assertion should succeed");
        assert_eq!(cmd.name(), expected_name);
    }

    fn assert_routing_rejected(args: Args) {
        assert!(CommandRouter::validate_routing(&args).is_err());
    }

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
        assert_routes_to(args, "PqcScanCommand");
    }

    #[cfg(feature = "monitoring")]
    #[test]
    fn test_route_modes() {
        for (case, args, expected_name) in [
            (
                "api server",
                Args {
                    api_server: ApiServerArgs {
                        enable: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "ApiServerCommand",
            ),
            (
                "worker",
                Args {
                    api_server: ApiServerArgs {
                        worker: true,
                        config: Some("api.toml".into()),
                        ..Default::default()
                    },
                    database: DatabaseArgs {
                        config: Some("database.toml".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "WorkerCommand",
            ),
            (
                "monitor",
                Args {
                    monitoring: MonitoringArgs {
                        enable: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "MonitorCommand",
            ),
            (
                "ct logs",
                Args {
                    ct_logs: CtLogsArgs {
                        enable: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "CtLogsCommand",
            ),
            (
                "analytics",
                Args {
                    compare: Some("1:2".to_string()),
                    ..Default::default()
                },
                "AnalyticsCommand",
            ),
            (
                "database",
                Args {
                    database: DatabaseArgs {
                        init: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "DatabaseCommand",
            ),
            (
                "mx",
                Args {
                    mx_domain: Some("example.com".to_string()),
                    ..Default::default()
                },
                "MxTestCommand",
            ),
            (
                "file",
                Args {
                    input_file: Some(std::path::PathBuf::from("targets.txt")),
                    ..Default::default()
                },
                "MassScanCommand",
            ),
            (
                "cidr",
                Args {
                    cidr: Some("192.0.2.0/24".to_string()),
                    ..Default::default()
                },
                "MassScanCommand",
            ),
            (
                "asn",
                Args {
                    asn: Some("AS13335".to_string()),
                    ..Default::default()
                },
                "MassScanCommand",
            ),
        ] {
            let cmd = CommandRouter::route(args).expect(case);
            assert_eq!(cmd.name(), expected_name, "{case}");
        }
    }

    #[test]
    fn test_validate_rejects_conflicting_scan_sources() {
        for args in [
            Args {
                target: Some("example.com:443".to_string()),
                cidr: Some("192.0.2.0/24".to_string()),
                ..Default::default()
            },
            Args {
                asn: Some("AS13335".to_string()),
                cidr: Some("192.0.2.0/24".to_string()),
                ..Default::default()
            },
            Args {
                input_file: Some(std::path::PathBuf::from("targets.txt")),
                asn: Some("AS13335".to_string()),
                ..Default::default()
            },
            Args {
                mx_domain: Some("example.com".to_string()),
                target: Some("example.com:443".to_string()),
                ..Default::default()
            },
            Args {
                compare: Some("1:2".to_string()),
                trends: Some("example.com:443:30".to_string()),
                ..Default::default()
            },
        ] {
            assert_routing_rejected(args);
        }
    }

    #[test]
    fn test_reject_database_action_with_bulk_scan_sources() {
        for args in [
            Args {
                cidr: Some("192.0.2.0/30".to_string()),
                database: DatabaseArgs {
                    init: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            Args {
                asn: Some("AS13335".to_string()),
                database: DatabaseArgs {
                    init: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        ] {
            assert!(CommandRouter::route(args).is_err());
        }
    }

    #[test]
    fn test_route_scan_target() {
        let args = Args {
            target: Some("example.com:443".to_string()),
            ..Default::default()
        };
        assert_routes_to(args, "ScanCommand");
    }

    #[test]
    fn test_route_scan_all_ips_uses_anycast_command() {
        let mut args = Args {
            target: Some("example.com:443".to_string()),
            ..Default::default()
        };
        args.network.scan_all_ips = true;
        assert_routes_to(args, "AnycastScanCommand");
    }

    #[test]
    fn test_validate_conflicting_modes() {
        assert_routing_rejected(Args {
            api_server: ApiServerArgs {
                enable: true,
                ..Default::default()
            },
            monitoring: MonitoringArgs {
                enable: true,
                ..Default::default()
            },
            ..Default::default()
        });
    }

    #[test]
    fn test_validate_mx_file_conflict() {
        assert_routing_rejected(Args {
            mx_domain: Some("example.com".to_string()),
            input_file: Some(std::path::PathBuf::from("targets.txt")),
            ..Default::default()
        });
    }

    #[test]
    fn test_validate_operational_mode_with_target_conflict() {
        assert_routing_rejected(Args {
            api_server: ApiServerArgs {
                enable: true,
                ..Default::default()
            },
            target: Some("example.com:443".to_string()),
            ..Default::default()
        });
    }

    #[test]
    fn test_validate_requires_target_or_mode() {
        assert_routing_rejected(Args::default());
    }
}
