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
    assert_eq!(event["fields"]["outcome"], "error");
    assert!(!stderr.contains("--worker requires --api-config"));
}
