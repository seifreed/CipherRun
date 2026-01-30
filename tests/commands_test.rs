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
    let mut args = Args::default();
    args.input_file = Some(PathBuf::from("targets.txt"));
    let cmd = MassScanCommand::new(args);
    assert_eq!(cmd.name(), "MassScanCommand");
}

#[test]
fn test_analytics_command_creation_and_name() {
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    let cmd = AnalyticsCommand::new(args);
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_database_command_creation_and_name() {
    let mut args = Args::default();
    args.database.init = true;
    let cmd = DatabaseCommand::new(args);
    assert_eq!(cmd.name(), "DatabaseCommand");
}

#[test]
fn test_monitor_command_creation_and_name() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    let cmd = MonitorCommand::new(args);
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_api_server_command_creation_and_name() {
    let mut args = Args::default();
    args.api_server.enable = true;
    let cmd = ApiServerCommand::new(args);
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_ct_logs_command_creation_and_name() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    let cmd = CtLogsCommand::new(args);
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_mx_test_command_creation_and_name() {
    let mut args = Args::default();
    args.mx_domain = Some("example.com".to_string());
    let cmd = MxTestCommand::new(args);
    assert_eq!(cmd.name(), "MxTestCommand");
}

// ============================================================================
// CommandRouter: Basic Routing Tests
// ============================================================================

#[test]
fn test_router_priority_1_api_server() {
    let mut args = Args::default();
    args.api_server.enable = true;
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_router_priority_2_monitor_with_enable() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_router_priority_2_monitor_with_test_alert() {
    let mut args = Args::default();
    args.monitoring.test_alert = true;
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_router_priority_3_ct_logs() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_router_priority_4_analytics_compare() {
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_priority_4_analytics_changes() {
    let mut args = Args::default();
    args.changes = Some("example.com:443:30".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_priority_4_analytics_trends() {
    let mut args = Args::default();
    args.trends = Some("example.com:443:30".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_priority_4_analytics_dashboard() {
    let mut args = Args::default();
    args.dashboard = Some("example.com:443:30".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_priority_5_database_init_only() {
    let mut args = Args::default();
    args.database.init = true;
    // No target specified
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "DatabaseCommand");
}

#[test]
fn test_router_priority_5_database_cleanup_only() {
    let mut args = Args::default();
    args.database.cleanup_days = Some(30);
    // No target specified
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "DatabaseCommand");
}

#[test]
fn test_router_priority_5_database_history_only() {
    let mut args = Args::default();
    args.database.history = Some("example.com:443".to_string());
    // No target specified
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "DatabaseCommand");
}

#[test]
fn test_router_priority_5_database_with_target_routes_to_scan() {
    let mut args = Args::default();
    args.database.init = true;
    args.target = Some("example.com:443".to_string());
    // With target, should route to ScanCommand
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_router_priority_6_mx_test() {
    let mut args = Args::default();
    args.mx_domain = Some("example.com".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MxTestCommand");
}

#[test]
fn test_router_priority_7_mass_scan() {
    let mut args = Args::default();
    args.input_file = Some(PathBuf::from("targets.txt"));
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MassScanCommand");
}

#[test]
fn test_router_priority_8_scan_default() {
    let args = Args::default();
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_router_priority_8_scan_with_target() {
    let mut args = Args::default();
    args.target = Some("example.com:443".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ScanCommand");
}

// ============================================================================
// CommandRouter: Priority Override Tests
// ============================================================================

#[test]
fn test_router_api_server_overrides_monitor() {
    let mut args = Args::default();
    args.api_server.enable = true;
    args.monitoring.enable = true;
    // Should route to ApiServerCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_router_monitor_overrides_ct_logs() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    args.ct_logs.enable = true;
    // Should route to MonitorCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_router_ct_logs_overrides_analytics() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    args.compare = Some("1:2".to_string());
    // Should route to CtLogsCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_router_analytics_overrides_database() {
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    args.database.init = true;
    // Should route to AnalyticsCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_mx_overrides_scan() {
    let mut args = Args::default();
    args.mx_domain = Some("example.com".to_string());
    args.target = Some("example.com:443".to_string());
    // Should route to MxTestCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MxTestCommand");
}

#[test]
fn test_router_mass_scan_overrides_scan() {
    let mut args = Args::default();
    args.input_file = Some(PathBuf::from("targets.txt"));
    args.target = Some("example.com:443".to_string());
    // Should route to MassScanCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MassScanCommand");
}

// ============================================================================
// CommandRouter: Validation Tests - Conflicting Modes
// ============================================================================

#[test]
fn test_validate_api_server_and_monitor_conflict() {
    let mut args = Args::default();
    args.api_server.enable = true;
    args.monitoring.enable = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Cannot combine multiple operational modes")
    );
}

#[test]
fn test_validate_api_server_and_ct_logs_conflict() {
    let mut args = Args::default();
    args.api_server.enable = true;
    args.ct_logs.enable = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
}

#[test]
fn test_validate_api_server_and_analytics_conflict() {
    let mut args = Args::default();
    args.api_server.enable = true;
    args.compare = Some("1:2".to_string());
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
}

#[test]
fn test_validate_monitor_and_ct_logs_conflict() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    args.ct_logs.enable = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
}

#[test]
fn test_validate_monitor_and_analytics_conflict() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    args.changes = Some("example.com:443:30".to_string());
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
}

#[test]
fn test_validate_ct_logs_and_analytics_conflict() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    args.trends = Some("example.com:443:30".to_string());
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
}

#[test]
fn test_validate_test_alert_and_api_server_conflict() {
    let mut args = Args::default();
    args.monitoring.test_alert = true;
    args.api_server.enable = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
}

// ============================================================================
// CommandRouter: Validation Tests - Scanning Mode Conflicts
// ============================================================================

#[test]
fn test_validate_mx_and_file_conflict() {
    let mut args = Args::default();
    args.mx_domain = Some("example.com".to_string());
    args.input_file = Some(PathBuf::from("targets.txt"));
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Cannot use --mx with --file")
    );
}

#[test]
fn test_validate_target_and_file_conflict() {
    let mut args = Args::default();
    args.target = Some("example.com:443".to_string());
    args.input_file = Some(PathBuf::from("targets.txt"));
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Cannot specify both target and --file")
    );
}

// ============================================================================
// CommandRouter: Validation Tests - Valid Combinations
// ============================================================================

#[test]
fn test_validate_scan_with_database_storage() {
    let mut args = Args::default();
    args.target = Some("example.com:443".to_string());
    args.database.store_results = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_mass_scan_with_parallel() {
    let mut args = Args::default();
    args.input_file = Some(PathBuf::from("targets.txt"));
    args.network.parallel = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_mx_with_parallel() {
    let mut args = Args::default();
    args.mx_domain = Some("example.com".to_string());
    args.network.parallel = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_api_server_standalone() {
    let mut args = Args::default();
    args.api_server.enable = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_monitor_standalone() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_ct_logs_standalone() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_database_init_standalone() {
    let mut args = Args::default();
    args.database.init = true;
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_analytics_compare_standalone() {
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_validate_empty_args() {
    let args = Args::default();
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

// ============================================================================
// CommandRouter: Analytics Argument Format Tests
// ============================================================================

#[test]
fn test_router_analytics_compare_format_validation() {
    // Valid compare format: "ID1:ID2"
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_analytics_changes_format_validation() {
    // Valid changes format: "HOSTNAME:PORT:DAYS"
    let mut args = Args::default();
    args.changes = Some("example.com:443:30".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_analytics_trends_format_validation() {
    // Valid trends format: "HOSTNAME:PORT:DAYS"
    let mut args = Args::default();
    args.trends = Some("example.com:443:7".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_analytics_dashboard_format_validation() {
    // Valid dashboard format: "HOSTNAME:PORT:DAYS"
    let mut args = Args::default();
    args.dashboard = Some("example.com:443:90".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_router_analytics_multiple_operations() {
    // Multiple analytics operations should still route to AnalyticsCommand
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    args.trends = Some("example.com:443:30".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

// ============================================================================
// Command Trait Object Tests
// ============================================================================

#[test]
fn test_command_trait_object_from_router() {
    let args = Args::default();
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    // Verify we can call trait methods on the boxed command
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_command_trait_object_api_server() {
    let mut args = Args::default();
    args.api_server.enable = true;
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_command_trait_object_monitor() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_command_trait_object_ct_logs() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_command_trait_object_analytics() {
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "AnalyticsCommand");
}

#[test]
fn test_command_trait_object_database() {
    let mut args = Args::default();
    args.database.init = true;
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "DatabaseCommand");
}

#[test]
fn test_command_trait_object_mx_test() {
    let mut args = Args::default();
    args.mx_domain = Some("example.com".to_string());
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MxTestCommand");
}

#[test]
fn test_command_trait_object_mass_scan() {
    let mut args = Args::default();
    args.input_file = Some(PathBuf::from("targets.txt"));
    let cmd: Box<dyn Command> = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MassScanCommand");
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_router_database_with_input_file_routes_to_mass_scan() {
    let mut args = Args::default();
    args.database.init = true;
    args.input_file = Some(PathBuf::from("targets.txt"));
    // With input file, should route to MassScanCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MassScanCommand");
}

#[test]
fn test_router_database_with_mx_routes_to_mx_test() {
    let mut args = Args::default();
    args.database.init = true;
    args.mx_domain = Some("example.com".to_string());
    // With MX domain, should route to MxTestCommand (higher priority)
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MxTestCommand");
}

#[test]
fn test_validate_all_analytics_options_together() {
    let mut args = Args::default();
    args.compare = Some("1:2".to_string());
    args.changes = Some("example.com:443:30".to_string());
    args.trends = Some("example.com:443:7".to_string());
    args.dashboard = Some("example.com:443:90".to_string());
    // Multiple analytics options should be valid (command handles precedence)
    let result = CommandRouter::validate_routing(&args);
    assert!(result.is_ok());
}

#[test]
fn test_router_with_port_override() {
    let mut args = Args::default();
    args.target = Some("example.com".to_string());
    args.port = Some(8443);
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_router_with_ip_override() {
    let mut args = Args::default();
    args.target = Some("example.com:443".to_string());
    args.ip = Some("192.168.1.1".to_string());
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_router_with_parallel_flag() {
    let mut args = Args::default();
    args.input_file = Some(PathBuf::from("targets.txt"));
    args.network.parallel = true;
    let cmd = CommandRouter::route(args).unwrap();
    assert_eq!(cmd.name(), "MassScanCommand");
}

// ============================================================================
// Command Construction with Complex Args Tests
// ============================================================================

#[test]
fn test_scan_command_with_output_options() {
    let mut args = Args::default();
    args.target = Some("example.com:443".to_string());
    args.output.json = Some(PathBuf::from("output.json"));
    args.output.json_pretty = true;
    let cmd = ScanCommand::new(args);
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_scan_command_with_compliance_options() {
    let mut args = Args::default();
    args.target = Some("example.com:443".to_string());
    args.compliance.framework = Some("pci-dss".to_string());
    args.compliance.format = "json".to_string();
    let cmd = ScanCommand::new(args);
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_scan_command_with_database_storage() {
    let mut args = Args::default();
    args.target = Some("example.com:443".to_string());
    args.database.store_results = true;
    args.database.config = Some(PathBuf::from("database.toml"));
    let cmd = ScanCommand::new(args);
    assert_eq!(cmd.name(), "ScanCommand");
}

#[test]
fn test_mass_scan_command_with_filters() {
    let mut args = Args::default();
    args.input_file = Some(PathBuf::from("targets.txt"));
    args.cert_filters.filter_expired = true;
    args.cert_filters.filter_self_signed = true;
    let cmd = MassScanCommand::new(args);
    assert_eq!(cmd.name(), "MassScanCommand");
}

#[test]
fn test_monitor_command_with_config_file() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    args.monitoring.config = Some(PathBuf::from("monitor.toml"));
    let cmd = MonitorCommand::new(args);
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_monitor_command_with_domain() {
    let mut args = Args::default();
    args.monitoring.enable = true;
    args.monitoring.domain = Some("example.com:443".to_string());
    let cmd = MonitorCommand::new(args);
    assert_eq!(cmd.name(), "MonitorCommand");
}

#[test]
fn test_api_server_command_with_custom_host_port() {
    let mut args = Args::default();
    args.api_server.enable = true;
    args.api_server.host = "127.0.0.1".to_string();
    args.api_server.port = 8080;
    let cmd = ApiServerCommand::new(args);
    assert_eq!(cmd.name(), "ApiServerCommand");
}

#[test]
fn test_ct_logs_command_with_custom_indices() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    args.ct_logs.index = vec!["google=12345".to_string(), "cloudflare=67890".to_string()];
    let cmd = CtLogsCommand::new(args);
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_ct_logs_command_with_beginning_flag() {
    let mut args = Args::default();
    args.ct_logs.enable = true;
    args.ct_logs.beginning = true;
    let cmd = CtLogsCommand::new(args);
    assert_eq!(cmd.name(), "CtLogsCommand");
}

#[test]
fn test_database_command_with_multiple_operations() {
    let mut args = Args::default();
    args.database.init = true;
    args.database.cleanup_days = Some(30);
    args.database.history = Some("example.com:443".to_string());
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
            {
                let mut args = Args::default();
                args.api_server.enable = true;
                args
            },
            "ApiServerCommand",
        ),
        (
            {
                let mut args = Args::default();
                args.monitoring.enable = true;
                args
            },
            "MonitorCommand",
        ),
        (
            {
                let mut args = Args::default();
                args.ct_logs.enable = true;
                args
            },
            "CtLogsCommand",
        ),
        (
            {
                let mut args = Args::default();
                args.compare = Some("1:2".to_string());
                args
            },
            "AnalyticsCommand",
        ),
        (
            {
                let mut args = Args::default();
                args.database.init = true;
                args
            },
            "DatabaseCommand",
        ),
        (
            {
                let mut args = Args::default();
                args.mx_domain = Some("example.com".to_string());
                args
            },
            "MxTestCommand",
        ),
        (
            {
                let mut args = Args::default();
                args.input_file = Some(PathBuf::from("targets.txt"));
                args
            },
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
