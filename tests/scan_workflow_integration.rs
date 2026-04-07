mod common;

use cipherrun::application::use_cases::{RunScan, ScanWorkflow};
use cipherrun::application::use_cases::scan_workflow::{ScanWorkflowInput, ScanWorkflowServices};
use cipherrun::application::ScanRequest;
use cipherrun::compliance::{BuiltinFrameworkSource, engine::DefaultComplianceEvaluator};
use common::mock_scanner::MockScannerPort;
use std::sync::Arc;

fn mock_services(scanner: Arc<MockScannerPort>) -> ScanWorkflowServices {
    ScanWorkflowServices {
        scanner_port: scanner,
        compliance_framework_source: None,
        compliance_evaluator: None,
        policy_source: None,
        policy_evaluator: None,
        scan_results_store_factory: None,
    }
}

#[tokio::test]
async fn test_workflow_with_mock_scanner() {
    let mock = Arc::new(MockScannerPort::default_success());
    let services = mock_services(mock);

    let input = ScanWorkflowInput {
        request: ScanRequest {
            target: Some("mock.example.com".to_string()),
            port: Some(443),
            ..Default::default()
        },
        ..Default::default()
    };

    let report = ScanWorkflow::execute(input, &services)
        .await
        .expect("workflow should succeed");
    assert_eq!(report.results().target, "mock.example.com:443");
    assert!(report.compliance_report().is_none());
    assert!(report.policy_result().is_none());
    assert!(report.stored_scan_id().is_none());
}

#[tokio::test]
async fn test_workflow_with_compliance_framework() {
    let mock = Arc::new(MockScannerPort::default_success());

    let input = ScanWorkflowInput {
        request: ScanRequest {
            target: Some("mock.example.com".to_string()),
            port: Some(443),
            ..Default::default()
        },
        compliance_framework: Some("nist-sp800-52r2".to_string()),
        ..Default::default()
    };
    let services = ScanWorkflowServices {
        scanner_port: mock,
        compliance_framework_source: Some(Arc::new(BuiltinFrameworkSource)),
        compliance_evaluator: Some(Arc::new(DefaultComplianceEvaluator)),
        policy_source: None,
        policy_evaluator: None,
        scan_results_store_factory: None,
    };

    let report = ScanWorkflow::execute(input, &services)
        .await
        .expect("workflow should succeed");
    assert!(report.compliance_report().is_some());
}

#[tokio::test]
async fn test_run_scan_with_injected_scanner() {
    let mock = MockScannerPort::default_success();

    let request = ScanRequest {
        target: Some("mock.example.com".to_string()),
        port: Some(443),
        ..Default::default()
    };

    let results = RunScan::execute(request, &mock)
        .await
        .expect("scan should succeed");
    assert_eq!(results.target, "mock.example.com:443");
}

#[tokio::test]
async fn test_workflow_rejects_store_without_db_config() {
    let mock = Arc::new(MockScannerPort::default_success());
    let services = mock_services(mock);

    let input = ScanWorkflowInput {
        store_results: true,
        database_config_path: None, // Missing!
        request: ScanRequest {
            target: Some("mock.example.com".to_string()),
            port: Some(443),
            ..Default::default()
        },
        ..Default::default()
    };

    let result = ScanWorkflow::execute(input, &services).await;
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.to_string().contains("database_config_path"));
}
