use std::process::Command;

#[test]
fn worker_emits_structured_failure_when_configuration_is_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_cipherrun-worker"))
        .arg("--worker")
        .env("RUST_LOG", "info")
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .output()
        .expect("worker process should start");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("logs should be UTF-8");
    let event: serde_json::Value = stderr
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .find(|event: &serde_json::Value| event["fields"]["event_name"] == "worker.failed")
        .expect("worker should emit a structured failure event");

    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["fields"]["error_type"], "TlsError");
    assert_eq!(event["fields"]["error_code"], "configuration_error");
    assert_eq!(event["fields"]["outcome"], "error");
    assert!(!stderr.contains("--worker requires --api-config"));
}

#[test]
fn worker_parse_failure_reports_safe_code_without_reflecting_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_cipherrun-worker"))
        .args(["--worker", "--invalid-option=secret-do-not-log"])
        .output()
        .expect("worker process should start");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("diagnostic should be UTF-8");
    assert!(stderr.contains("error_code=configuration_error"));
    assert!(!stderr.contains("secret-do-not-log"));
}

#[test]
fn worker_continues_with_stderr_when_logfile_cannot_be_opened() {
    let output = Command::new(env!("CARGO_BIN_EXE_cipherrun-worker"))
        .args(["--worker", "--logfile", "."])
        .env("RUST_LOG", "info")
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .output()
        .expect("worker process should start");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("logs should be UTF-8");
    let events = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    assert!(events.iter().any(|event| {
        event["level"] == "WARN"
            && event["fields"]["event_name"] == "logging.file_destination.failed"
            && event["fields"]["error_code"] == "filesystem_error"
            && event["fields"]["outcome"] == "stderr_only"
    }));
    assert!(events.iter().any(|event| {
        event["level"] == "ERROR" && event["fields"]["event_name"] == "worker.failed"
    }));
}

#[cfg(feature = "otel")]
#[test]
fn worker_continues_with_local_logs_when_otlp_setup_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_cipherrun-worker"))
        .arg("--worker")
        .env("RUST_LOG", "info")
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_COMPRESSION")
        .env("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")
        .output()
        .expect("worker process should start");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("logs should be UTF-8");
    let events = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    assert!(
        events.iter().any(|event| {
            event["level"] == "WARN"
                && event["fields"]["event_name"] == "telemetry.exporter.initialization_failed"
                && event["fields"]["outcome"] == "local_logging_only"
        }),
        "{stderr}"
    );
    assert!(events.iter().any(|event| {
        event["level"] == "ERROR" && event["fields"]["event_name"] == "worker.failed"
    }));
    assert!(!stderr.contains("gzip-http"));
}
