// Copyright (c) 2025 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

//! Commands Module Integration Tests
//!
//! Tests the Command Pattern implementation for CipherRun's operational modes.
//! This test suite validates:
//! - Command creation and naming
//! - Command router logic and priority-based routing
//! - Argument validation and conflict detection
//! - Each command type can be instantiated correctly
//!
//! All tests use real Args structures and actual command implementations.

use cipherrun::Args;
use cipherrun::commands::{
    AnalyticsCommand, ApiServerCommand, Command, CommandRouter, CtLogsCommand, DatabaseCommand,
    MassScanCommand, MonitorCommand, MxTestCommand, ScanCommand,
};
use std::path::PathBuf;

fn build_args(configure: impl FnOnce(&mut Args)) -> Args {
    let mut args = Args::default();
    configure(&mut args);
    args
}

fn route_name(args: Args) -> String {
    CommandRouter::route(args).unwrap().name().to_string()
}

fn route_command(args: Args) -> Box<dyn Command> {
    CommandRouter::route(args).unwrap()
}

fn validate_ok(args: Args) {
    assert!(CommandRouter::validate_routing(&args).is_ok());
}

fn validate_err(args: Args) -> String {
    CommandRouter::validate_routing(&args)
        .unwrap_err()
        .to_string()
}

// ============================================================================
// Command Creation and Naming Tests
// ============================================================================

#[test]
fn test_scan_command_creation_and_name() {
    let args = Args::default();
    let cmd = ScanCommand::new(args);
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_mass_scan_command_creation_and_name() {
    let args = build_args(|args| {
        args.input_file = Some(PathBuf::from("targets.txt"));
    });
    let cmd = MassScanCommand::new(args);
    assert_eq!(cmd.name(), "MassScanCommand");
}

#[test]
fn test_analytics_command_creation_and_name() {
    let args = build_args(|args| {
        args.compare = Some("1:2".to_string());
    });
    let cmd = AnalyticsCommand::new(args);
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_database_command_creation_and_name() {
    let args = build_args(|args| {
        args.database.init = true;
    });
    let cmd = DatabaseCommand::new(args);
    assert_eq!(cmd.name(), "DatabaseCommand");
}

#[test]
fn test_monitor_command_creation_and_name() {
    let args = build_args(|args| {
        args.monitoring.enable = true;
    });
    let cmd = MonitorCommand::new(args);
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_api_server_command_creation_and_name() {
    let args = build_args(|args| {
        args.api_server.enable = true;
    });
    let cmd = ApiServerCommand::new(args);
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_ct_logs_command_creation_and_name() {
    let args = build_args(|args| {
        args.ct_logs.enable = true;
    });
    let cmd = CtLogsCommand::new(args);
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_mx_test_command_creation_and_name() {
    let args = build_args(|args| {
        args.mx_domain = Some("example.com".to_string());
    });
    let cmd = MxTestCommand::new(args);
    assert_eq!(cmd.name(), "MxTestCommand");
}

// ============================================================================
// CommandRouter: Basic Routing Tests
// ============================================================================

#[test]
fn test_router_priority_1_api_server() {
    assert_eq!(
        route_name(build_args(|args| args.api_server.enable = true)),
        "ApiServerCommand"
    );
}

#[test]
fn test_router_priority_2_monitor_with_enable() {
    assert_eq!(
        route_name(build_args(|args| args.monitoring.enable = true)),
        "MonitorCommand"
    );
}

#[test]
fn test_router_priority_2_monitor_with_test_alert() {
    assert_eq!(
        route_name(build_args(|args| args.monitoring.test_alert = true)),
        "MonitorCommand"
    );
}

#[test]
fn test_router_priority_3_ct_logs() {
    assert_eq!(
        route_name(build_args(|args| args.ct_logs.enable = true)),
        "CtLogsCommand"
    );
}

#[test]
fn test_router_priority_4_analytics_compare() {
    assert_eq!(
        route_name(build_args(|args| args.compare = Some("1:2".to_string()))),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_priority_4_analytics_changes() {
    assert_eq!(
        route_name(build_args(|args| {
            args.changes = Some("example.com:443:30".to_string())
        })),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_priority_4_analytics_trends() {
    assert_eq!(
        route_name(build_args(|args| {
            args.trends = Some("example.com:443:30".to_string())
        })),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_priority_4_analytics_dashboard() {
    assert_eq!(
        route_name(build_args(|args| {
            args.dashboard = Some("example.com:443:30".to_string())
        })),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_priority_5_database_init_only() {
    assert_eq!(
        route_name(build_args(|args| args.database.init = true)),
        "DatabaseCommand"
    );
}

#[test]
fn test_router_priority_5_database_cleanup_only() {
    assert_eq!(
        route_name(build_args(|args| args.database.cleanup_days = Some(30))),
        "DatabaseCommand"
    );
}

#[test]
fn test_router_priority_5_database_history_only() {
    assert_eq!(
        route_name(build_args(|args| {
            args.database.history = Some("example.com:443".to_string())
        })),
        "DatabaseCommand"
    );
}

#[test]
fn test_router_priority_5_database_with_target_routes_to_scan() {
    assert_eq!(
        route_name(build_args(|args| {
            args.database.init = true;
            args.target = Some("example.com:443".to_string());
        })),
        "ScanCommand"
    );
}

#[test]
fn test_router_priority_6_mx_test() {
    assert_eq!(
        route_name(build_args(|args| {
            args.mx_domain = Some("example.com".to_string())
        })),
        "MxTestCommand"
    );
}

#[test]
fn test_router_priority_7_mass_scan() {
    assert_eq!(
        route_name(build_args(|args| {
            args.input_file = Some(PathBuf::from("targets.txt"))
        })),
        "MassScanCommand"
    );
}

#[test]
fn test_router_priority_8_scan_default() {
    assert_eq!(route_name(Args::default()), "ScanCommand");
}

#[test]
fn test_router_priority_8_scan_with_target() {
    assert_eq!(
        route_name(build_args(|args| {
            args.target = Some("example.com:443".to_string())
        })),
        "ScanCommand"
    );
}

// ============================================================================
// CommandRouter: Priority Override Tests
// ============================================================================

#[test]
fn test_router_rejects_api_server_and_monitor() {
    let err = CommandRouter::route(build_args(|args| {
        args.api_server.enable = true;
        args.monitoring.enable = true;
    }));
    assert!(err.is_err());
}

#[test]
fn test_router_rejects_monitor_and_ct_logs() {
    let err = CommandRouter::route(build_args(|args| {
        args.monitoring.enable = true;
        args.ct_logs.enable = true;
    }));
    assert!(err.is_err());
}

#[test]
fn test_router_rejects_ct_logs_and_analytics() {
    let err = CommandRouter::route(build_args(|args| {
        args.ct_logs.enable = true;
        args.compare = Some("1:2".to_string());
    }));
    assert!(err.is_err());
}

#[test]
fn test_router_rejects_analytics_and_database() {
    let err = CommandRouter::route(build_args(|args| {
        args.compare = Some("1:2".to_string());
        args.database.init = true;
    }));
    assert!(err.is_err());
}

#[test]
fn test_router_mx_overrides_scan() {
    assert_eq!(
        route_name(build_args(|args| {
            args.mx_domain = Some("example.com".to_string());
            args.target = Some("example.com:443".to_string());
        })),
        "MxTestCommand"
    );
}

#[test]
fn test_router_rejects_mass_scan_and_target() {
    let err = CommandRouter::route(build_args(|args| {
        args.input_file = Some(PathBuf::from("targets.txt"));
        args.target = Some("example.com:443".to_string());
    }));
    assert!(err.is_err());
}

// ============================================================================
// CommandRouter: Validation Tests - Conflicting Modes
// ============================================================================

#[test]
fn test_validate_api_server_and_monitor_conflict() {
    let error = validate_err(build_args(|args| {
        args.api_server.enable = true;
        args.monitoring.enable = true;
    }));
    assert!(error.contains("Cannot combine multiple operational modes"));
}

#[test]
fn test_validate_api_server_and_ct_logs_conflict() {
    let _ = validate_err(build_args(|args| {
        args.api_server.enable = true;
        args.ct_logs.enable = true;
    }));
}

#[test]
fn test_validate_api_server_and_analytics_conflict() {
    let _ = validate_err(build_args(|args| {
        args.api_server.enable = true;
        args.compare = Some("1:2".to_string());
    }));
}

#[test]
fn test_validate_monitor_and_ct_logs_conflict() {
    let _ = validate_err(build_args(|args| {
        args.monitoring.enable = true;
        args.ct_logs.enable = true;
    }));
}

#[test]
fn test_validate_monitor_and_analytics_conflict() {
    let _ = validate_err(build_args(|args| {
        args.monitoring.enable = true;
        args.changes = Some("example.com:443:30".to_string());
    }));
}

#[test]
fn test_validate_ct_logs_and_analytics_conflict() {
    let _ = validate_err(build_args(|args| {
        args.ct_logs.enable = true;
        args.trends = Some("example.com:443:30".to_string());
    }));
}

#[test]
fn test_validate_test_alert_and_api_server_conflict() {
    let _ = validate_err(build_args(|args| {
        args.monitoring.test_alert = true;
        args.api_server.enable = true;
    }));
}

// ============================================================================
// CommandRouter: Validation Tests - Scanning Mode Conflicts
// ============================================================================

#[test]
fn test_validate_mx_and_file_conflict() {
    let error = validate_err(build_args(|args| {
        args.mx_domain = Some("example.com".to_string());
        args.input_file = Some(PathBuf::from("targets.txt"));
    }));
    assert!(error.contains("Cannot use --mx with --file"));
}

#[test]
fn test_validate_target_and_file_conflict() {
    let error = validate_err(build_args(|args| {
        args.target = Some("example.com:443".to_string());
        args.input_file = Some(PathBuf::from("targets.txt"));
    }));
    assert!(error.contains("Cannot specify both target and --file"));
}

// ============================================================================
// CommandRouter: Validation Tests - Valid Combinations
// ============================================================================

#[test]
fn test_validate_scan_with_database_storage() {
    validate_ok(build_args(|args| {
        args.target = Some("example.com:443".to_string());
        args.database.store_results = true;
    }));
}

#[test]
fn test_validate_mass_scan_with_parallel() {
    validate_ok(build_args(|args| {
        args.input_file = Some(PathBuf::from("targets.txt"));
        args.network.parallel = true;
    }));
}

#[test]
fn test_validate_mx_with_parallel() {
    validate_ok(build_args(|args| {
        args.mx_domain = Some("example.com".to_string());
        args.network.parallel = true;
    }));
}

#[test]
fn test_validate_api_server_standalone() {
    validate_ok(build_args(|args| args.api_server.enable = true));
}

#[test]
fn test_validate_monitor_standalone() {
    validate_ok(build_args(|args| args.monitoring.enable = true));
}

#[test]
fn test_validate_ct_logs_standalone() {
    validate_ok(build_args(|args| args.ct_logs.enable = true));
}

#[test]
fn test_validate_database_init_standalone() {
    validate_ok(build_args(|args| args.database.init = true));
}

#[test]
fn test_validate_analytics_compare_standalone() {
    validate_ok(build_args(|args| args.compare = Some("1:2".to_string())));
}

#[test]
fn test_validate_empty_args() {
    validate_ok(Args::default());
}

// ============================================================================
// CommandRouter: Analytics Argument Format Tests
// ============================================================================

#[test]
fn test_router_analytics_compare_format_validation() {
    assert_eq!(
        route_name(build_args(|args| args.compare = Some("1:2".to_string()))),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_analytics_changes_format_validation() {
    assert_eq!(
        route_name(build_args(|args| {
            args.changes = Some("example.com:443:30".to_string())
        })),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_analytics_trends_format_validation() {
    assert_eq!(
        route_name(build_args(|args| {
            args.trends = Some("example.com:443:7".to_string())
        })),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_analytics_dashboard_format_validation() {
    assert_eq!(
        route_name(build_args(|args| {
            args.dashboard = Some("example.com:443:90".to_string())
        })),
        "AnalyticsCommand"
    );
}

#[test]
fn test_router_analytics_multiple_operations() {
    assert_eq!(
        route_name(build_args(|args| {
            args.compare = Some("1:2".to_string());
            args.trends = Some("example.com:443:30".to_string());
        })),
        "AnalyticsCommand"
    );
}

// ============================================================================
// Command Trait Object Tests
// ============================================================================

#[test]
fn test_command_trait_object_from_router() {
    let args = Args::default();
    let cmd = route_command(args);
    // Verify we can call trait methods on the boxed command
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_command_trait_object_api_server() {
    let cmd = route_command(build_args(|args| args.api_server.enable = true));
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_command_trait_object_monitor() {
    let cmd = route_command(build_args(|args| args.monitoring.enable = true));
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_command_trait_object_ct_logs() {
    let cmd = route_command(build_args(|args| args.ct_logs.enable = true));
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_command_trait_object_analytics() {
    let cmd = route_command(build_args(|args| args.compare = Some("1:2".to_string())));
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_command_trait_object_database() {
    let cmd = route_command(build_args(|args| args.database.init = true));
    assert_eq!(cmd.name(), "DatabaseCommand");
}

#[test]
fn test_command_trait_object_mx_test() {
    let cmd = route_command(build_args(|args| {
        args.mx_domain = Some("example.com".to_string())
    }));
    assert_eq!(cmd.name(), "MxTestCommand");
}

#[test]
fn test_command_trait_object_mass_scan() {
    let cmd = route_command(build_args(|args| {
        args.input_file = Some(PathBuf::from("targets.txt"))
    }));
    assert_eq!(cmd.name(), "MassScanCommand");
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_router_database_with_input_file_routes_to_mass_scan() {
    assert_eq!(
        route_name(build_args(|args| {
            args.database.init = true;
            args.input_file = Some(PathBuf::from("targets.txt"));
        })),
        "MassScanCommand"
    );
}

#[test]
fn test_router_database_with_mx_routes_to_mx_test() {
    assert_eq!(
        route_name(build_args(|args| {
            args.database.init = true;
            args.mx_domain = Some("example.com".to_string());
        })),
        "MxTestCommand"
    );
}

#[test]
fn test_validate_all_analytics_options_together() {
    validate_ok(build_args(|args| {
        args.compare = Some("1:2".to_string());
        args.changes = Some("example.com:443:30".to_string());
        args.trends = Some("example.com:443:7".to_string());
        args.dashboard = Some("example.com:443:90".to_string());
    }));
}

#[test]
fn test_router_with_port_override() {
    assert_eq!(
        route_name(build_args(|args| {
            args.target = Some("example.com".to_string());
            args.port = Some(8443);
        })),
        "ScanCommand"
    );
}

#[test]
fn test_router_with_ip_override() {
    assert_eq!(
        route_name(build_args(|args| {
            args.target = Some("example.com:443".to_string());
            args.ip = Some("192.168.1.1".to_string());
        })),
        "ScanCommand"
    );
}

#[test]
fn test_router_with_parallel_flag() {
    assert_eq!(
        route_name(build_args(|args| {
            args.input_file = Some(PathBuf::from("targets.txt"));
            args.network.parallel = true;
        })),
        "MassScanCommand"
    );
}

// ============================================================================
// Command Construction with Complex Args Tests
// ============================================================================

#[test]
fn test_scan_command_with_output_options() {
    let args = build_args(|args| {
        args.target = Some("example.com:443".to_string());
        args.output.json = Some(PathBuf::from("output.json"));
        args.output.json_pretty = true;
    });
    let cmd = ScanCommand::new(args);
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_scan_command_with_compliance_options() {
    let args = build_args(|args| {
        args.target = Some("example.com:443".to_string());
        args.compliance.framework = Some("pci-dss".to_string());
        args.compliance.format = "json".to_string();
    });
    let cmd = ScanCommand::new(args);
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_scan_command_with_database_storage() {
    let args = build_args(|args| {
        args.target = Some("example.com:443".to_string());
        args.database.store_results = true;
        args.database.config = Some(PathBuf::from("database.toml"));
    });
    let cmd = ScanCommand::new(args);
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_mass_scan_command_with_filters() {
    let args = build_args(|args| {
        args.input_file = Some(PathBuf::from("targets.txt"));
        args.cert_filters.filter_expired = true;
        args.cert_filters.filter_self_signed = true;
    });
    let cmd = MassScanCommand::new(args);
    assert_eq!(cmd.name(), "MassScanCommand");
}

#[test]
fn test_monitor_command_with_config_file() {
    let args = build_args(|args| {
        args.monitoring.enable = true;
        args.monitoring.config = Some(PathBuf::from("monitor.toml"));
    });
    let cmd = MonitorCommand::new(args);
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_monitor_command_with_domain() {
    let args = build_args(|args| {
        args.monitoring.enable = true;
        args.monitoring.domain = Some("example.com:443".to_string());
    });
    let cmd = MonitorCommand::new(args);
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_api_server_command_with_custom_host_port() {
    let args = build_args(|args| {
        args.api_server.enable = true;
        args.api_server.host = "127.0.0.1".to_string();
        args.api_server.port = 8080;
    });
    let cmd = ApiServerCommand::new(args);
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_ct_logs_command_with_custom_indices() {
    let args = build_args(|args| {
        args.ct_logs.enable = true;
        args.ct_logs.index = vec!["google=12345".to_string(), "cloudflare=67890".to_string()];
    });
    let cmd = CtLogsCommand::new(args);
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_ct_logs_command_with_beginning_flag() {
    let args = build_args(|args| {
        args.ct_logs.enable = true;
        args.ct_logs.beginning = true;
    });
    let cmd = CtLogsCommand::new(args);
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_database_command_with_multiple_operations() {
    let args = build_args(|args| {
        args.database.init = true;
        args.database.cleanup_days = Some(30);
        args.database.history = Some("example.com:443".to_string());
    });
    let cmd = DatabaseCommand::new(args);
    assert_eq!(cmd.name(), "DatabaseCommand");
}

// ============================================================================
// Comprehensive Routing Coverage Tests
// ============================================================================

#[test]
fn test_comprehensive_routing_coverage_all_commands() {
    // Test that we can route to every command type
    let command_configs = vec![
        (
            build_args(|args| args.api_server.enable = true),
            "ApiServerCommand",
        ),
        (
            build_args(|args| args.monitoring.enable = true),
            "MonitorCommand",
        ),
        (
            build_args(|args| args.ct_logs.enable = true),
            "CtLogsCommand",
        ),
        (
            build_args(|args| args.compare = Some("1:2".to_string())),
            "AnalyticsCommand",
        ),
        (
            build_args(|args| args.database.init = true),
            "DatabaseCommand",
        ),
        (
            build_args(|args| args.mx_domain = Some("example.com".to_string())),
            "MxTestCommand",
        ),
        (
            build_args(|args| args.input_file = Some(PathBuf::from("targets.txt"))),
            "MassScanCommand",
        ),
        (Args::default(), "ScanCommand"),
    ];

    for (args, expected_name) in command_configs {
        let cmd = CommandRouter::route(args).unwrap();
        assert_eq!(
            cmd.name(),
            expected_name,
            "Expected {} but got {}",
            expected_name,
            cmd.name()
        );
    }
}
