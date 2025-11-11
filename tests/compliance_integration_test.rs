// Integration tests for compliance framework engine

#![allow(clippy::field_reassign_with_default)]

use cipherrun::compliance::{
    ComplianceEngine, ComplianceStatus, FrameworkLoader, Reporter, RequirementStatus,
};
use cipherrun::protocols::{Protocol, ProtocolTestResult};
use cipherrun::scanner::ScanResults;

#[test]
fn test_load_all_builtin_frameworks() {
    let framework_ids = vec![
        "pci-dss-v4",
        "nist-sp800-52r2",
        "hipaa",
        "soc2",
        "mozilla-modern",
        "mozilla-intermediate",
        "gdpr",
    ];

    for framework_id in framework_ids {
        let result = FrameworkLoader::load_builtin(framework_id);
        assert!(
            result.is_ok(),
            "Failed to load framework {}: {:?}",
            framework_id,
            result.err()
        );

        let framework = result.unwrap();
        assert_eq!(framework.id, framework_id);
        assert!(!framework.name.is_empty());
        assert!(!framework.requirements.is_empty());
    }
}

#[test]
fn test_pci_dss_pass_scenario() {
    // Load PCI-DSS framework
    let framework = FrameworkLoader::load_builtin("pci-dss-v4").unwrap();

    // Create compliant scan results
    let mut results = ScanResults::default();
    results.target = "secure.example.com:443".to_string();

    // Only TLS 1.2 and TLS 1.3 enabled (compliant)
    results.protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: false,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
        ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
    ];

    // Evaluate compliance
    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Should pass protocol requirements at minimum
    assert!(report.summary.total > 0);
    // At least some requirements should pass
    assert!(report.summary.passed > 0);
}

#[test]
fn test_pci_dss_fail_scenario() {
    // Load PCI-DSS framework
    let framework = FrameworkLoader::load_builtin("pci-dss-v4").unwrap();

    // Create non-compliant scan results
    let mut results = ScanResults::default();
    results.target = "insecure.example.com:443".to_string();

    // TLS 1.0 enabled (non-compliant)
    results.protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::TLS10,
            supported: true,
            preferred: false,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
        ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: true,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
    ];

    // Evaluate compliance
    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Should fail due to TLS 1.0
    assert_eq!(report.overall_status, ComplianceStatus::Fail);
    assert!(report.summary.failed > 0);

    // Should have violations
    let failed_reqs = report.failed_requirements();
    assert!(!failed_reqs.is_empty());

    // Check that we have protocol-related violations
    let has_protocol_violation = failed_reqs.iter().any(|r| r.category.contains("Protocol"));
    assert!(has_protocol_violation);
}

#[test]
fn test_mozilla_modern_tls13_only() {
    // Load Mozilla Modern framework
    let framework = FrameworkLoader::load_builtin("mozilla-modern").unwrap();

    // TLS 1.2 enabled (should fail for Modern profile)
    let mut results = ScanResults::default();
    results.target = "test.example.com:443".to_string();
    results.protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: false,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
        ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
    ];

    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Mozilla Modern requires TLS 1.3 ONLY - TLS 1.2 should cause failure
    assert_eq!(report.overall_status, ComplianceStatus::Fail);
}

#[test]
fn test_mozilla_intermediate_tls12_allowed() {
    // Load Mozilla Intermediate framework
    let framework = FrameworkLoader::load_builtin("mozilla-intermediate").unwrap();

    // TLS 1.2 and TLS 1.3 enabled (compliant for Intermediate)
    let mut results = ScanResults::default();
    results.target = "test.example.com:443".to_string();
    results.protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: false,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
        ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
    ];

    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Should pass protocol requirements (TLS 1.2 is allowed in Intermediate)
    // Note: May still have warnings for other requirements
    let protocol_req = report
        .requirements
        .iter()
        .find(|r| r.category.contains("Protocol"));

    if let Some(req) = protocol_req {
        assert_ne!(req.status, RequirementStatus::Fail);
    }
}

#[test]
fn test_report_json_serialization() {
    let framework = FrameworkLoader::load_builtin("pci-dss-v4").unwrap();

    let mut results = ScanResults::default();
    results.target = "test.example.com:443".to_string();
    results.protocols = vec![ProtocolTestResult {
        protocol: Protocol::TLS12,
        supported: true,
        preferred: true,
        ciphers_count: 0,
        heartbeat_enabled: None,
        handshake_time_ms: None,
    }];

    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Test JSON serialization
    let json = Reporter::to_json(&report, false).unwrap();
    assert!(json.contains("pci-dss-v4"));
    assert!(json.contains("test.example.com"));

    // Test pretty JSON
    let json_pretty = Reporter::to_json(&report, true).unwrap();
    assert!(json_pretty.contains("pci-dss-v4"));
    assert!(json_pretty.len() > json.len()); // Pretty version should be longer
}

#[test]
fn test_report_csv_generation() {
    let framework = FrameworkLoader::load_builtin("nist-sp800-52r2").unwrap();

    let mut results = ScanResults::default();
    results.target = "test.example.com:443".to_string();
    results.protocols = vec![ProtocolTestResult {
        protocol: Protocol::TLS13,
        supported: true,
        preferred: true,
        ciphers_count: 0,
        heartbeat_enabled: None,
        handshake_time_ms: None,
    }];

    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Test CSV generation
    let csv = Reporter::to_csv(&report).unwrap();
    assert!(csv.contains("Requirement ID,Name,Category"));
    assert!(csv.contains("NIST-"));
}

#[test]
fn test_report_html_generation() {
    let framework = FrameworkLoader::load_builtin("hipaa").unwrap();

    let mut results = ScanResults::default();
    results.target = "test.example.com:443".to_string();
    results.protocols = vec![ProtocolTestResult {
        protocol: Protocol::TLS12,
        supported: true,
        preferred: true,
        ciphers_count: 0,
        heartbeat_enabled: None,
        handshake_time_ms: None,
    }];

    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Test HTML generation
    let html = Reporter::to_html(&report).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("HIPAA"));
    assert!(html.contains("test.example.com"));
}

#[test]
fn test_report_terminal_output() {
    let framework = FrameworkLoader::load_builtin("soc2").unwrap();

    let mut results = ScanResults::default();
    results.target = "test.example.com:443".to_string();
    results.protocols = vec![ProtocolTestResult {
        protocol: Protocol::TLS12,
        supported: true,
        preferred: true,
        ciphers_count: 0,
        heartbeat_enabled: None,
        handshake_time_ms: None,
    }];

    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Test terminal output
    let terminal = Reporter::to_terminal(&report);
    assert!(terminal.contains("SOC 2"));
    assert!(terminal.contains("test.example.com"));
    assert!(terminal.contains("Summary"));
}

#[test]
fn test_framework_loader_list() {
    let frameworks = FrameworkLoader::list_builtin_frameworks();

    assert_eq!(frameworks.len(), 7);

    // Check all expected frameworks are listed
    let ids: Vec<&str> = frameworks.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&"pci-dss-v4"));
    assert!(ids.contains(&"nist-sp800-52r2"));
    assert!(ids.contains(&"hipaa"));
    assert!(ids.contains(&"soc2"));
    assert!(ids.contains(&"mozilla-modern"));
    assert!(ids.contains(&"mozilla-intermediate"));
    assert!(ids.contains(&"gdpr"));
}

#[test]
fn test_invalid_framework_id() {
    let result = FrameworkLoader::load_builtin("invalid-framework-xyz");
    assert!(result.is_err());
}

#[test]
fn test_compliance_summary_calculation() {
    let framework = FrameworkLoader::load_builtin("gdpr").unwrap();

    let mut results = ScanResults::default();
    results.target = "test.example.com:443".to_string();
    results.protocols = vec![
        ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: false,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
        ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 0,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        },
    ];

    let engine = ComplianceEngine::new(framework);
    let report = engine.evaluate(&results).unwrap();

    // Verify summary counts add up
    assert_eq!(
        report.summary.total,
        report.summary.passed
            + report.summary.failed
            + report.summary.warnings
            + report.summary.not_applicable
    );

    // Verify requirements list matches summary total
    assert_eq!(report.summary.total, report.requirements.len());
}
