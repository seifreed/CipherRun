mod common;

use async_trait::async_trait;
use cipherrun::application::ScanRequest;
use cipherrun::application::ports::ScannerPort;
use cipherrun::application::use_cases::scan_workflow::{ScanWorkflowInput, ScanWorkflowServices};
use cipherrun::application::use_cases::{RunScan, ScanWorkflow};
use cipherrun::compliance::{BuiltinFrameworkSource, engine::DefaultComplianceEvaluator};
use cipherrun::scanner::ScanResults;
use common::mock_scanner::MockScannerPort;
use std::future::Future;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for CapturedOutput {
    type Writer = CapturedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedWriter(self.0.clone())
    }
}

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn run_with_captured_logs<T>(future: impl Future<Output = T>) -> (T, String) {
    let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_writer(output.clone())
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(future.with_subscriber(tracing::Dispatch::new(subscriber)));
    let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    (result, output)
}

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

struct CountingScannerPort {
    calls: Arc<AtomicUsize>,
    results: ScanResults,
}

#[async_trait]
impl ScannerPort for CountingScannerPort {
    async fn scan(&self, _request: ScanRequest) -> cipherrun::Result<ScanResults> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.results.clone())
    }
}

#[test]
fn test_workflow_with_mock_scanner() {
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

    let (report, output) = run_with_captured_logs(ScanWorkflow::execute(input, &services));
    let report = report.expect("workflow should succeed");
    assert_eq!(report.results().target, "mock.example.com:443");
    assert!(report.compliance_report().is_none());
    assert!(report.policy_result().is_none());
    assert!(report.stored_scan_id().is_none());
    let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(event["level"], "INFO");
    assert_eq!(event["fields"]["event_name"], "scan.workflow.finished");
    assert_eq!(event["fields"]["operation"], "scan_workflow");
    assert_eq!(event["fields"]["outcome"], "success");
    assert_eq!(event["fields"]["compliance_requested"], false);
    assert_eq!(event["fields"]["policy_requested"], false);
    assert_eq!(event["fields"]["persistence_requested"], false);
    assert!(event["fields"]["duration_ms"].is_number());
    assert!(!output.contains("mock.example.com"));
}

#[test]
fn test_workflow_logs_expected_configuration_failure_safely() {
    let scanner = Arc::new(MockScannerPort::default_success());
    let services = mock_services(scanner);
    let input = ScanWorkflowInput {
        request: ScanRequest {
            target: Some("private-target.example".to_string()),
            ..Default::default()
        },
        store_results: true,
        database_config_path: None,
        ..Default::default()
    };

    let (result, output) = run_with_captured_logs(ScanWorkflow::execute(input, &services));
    assert!(result.is_err());
    let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(event["level"], "WARN");
    assert_eq!(event["fields"]["event_name"], "scan.workflow.failed");
    assert_eq!(event["fields"]["error_code"], "configuration_error");
    assert_eq!(event["fields"]["outcome"], "failed");
    assert!(event["fields"]["duration_ms"].is_number());
    assert!(!output.contains("private-target.example"));
    assert!(!output.contains("database_config_path"));
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
    let calls = Arc::new(AtomicUsize::new(0));
    let scanner = Arc::new(CountingScannerPort {
        calls: calls.clone(),
        results: ScanResults {
            target: "mock.example.com:443".to_string(),
            scan_time_ms: 100,
            ..Default::default()
        },
    });
    let services = ScanWorkflowServices {
        scanner_port: scanner,
        compliance_framework_source: None,
        compliance_evaluator: None,
        policy_source: None,
        policy_evaluator: None,
        scan_results_store_factory: None,
    };

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
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
