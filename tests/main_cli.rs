use std::process::{Command, Stdio};
use tempfile::tempdir;

#[test]
fn test_main_version_output() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let output = Command::new(exe)
        .arg("--version")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CipherRun v"));
    assert!(stdout.contains("Fast, Modular TLS/SSL Security Scanner"));
}

#[test]
fn logger_lifecycle_events_stay_on_stderr() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let output = Command::new(exe)
        .arg("--version")
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("CLI output should be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    assert!(stdout.contains("CipherRun v"));
    assert!(!stdout.contains("logging.subscriber."));

    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("stderr events should be JSON"))
        .collect();
    let initialized = events
        .iter()
        .find(|event| event["fields"]["event_name"] == "logging.subscriber.initialized")
        .expect("subscriber initialization should be observable");
    assert_eq!(initialized["level"], "INFO");
    assert_eq!(initialized["fields"]["outcome"], "started");
    assert_eq!(initialized["fields"]["format"], "json");

    let shutdown = events
        .iter()
        .find(|event| event["fields"]["event_name"] == "logging.subscriber.shutdown")
        .expect("subscriber shutdown should be observable");
    assert_eq!(shutdown["level"], "INFO");
    assert_eq!(shutdown["fields"]["outcome"], "flush_requested");
}

#[test]
fn test_main_list_compliance_output() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let output = Command::new(exe)
        .arg("--list-compliance")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Available Compliance Frameworks"));
    assert!(stdout.contains("Usage: cipherrun --compliance"));
}

#[test]
fn test_main_show_ciphers_output() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let output = Command::new(exe)
        .arg("--show-ciphers")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Supported Cipher Suites"));
    assert!(stdout.contains("Total:"));
}

#[test]
fn test_main_api_config_example() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let dir = tempdir().expect("test assertion should succeed");
    let config_path = dir.path().join("api-config.toml");

    let output = Command::new(exe)
        .arg("--api-config-example")
        .arg(&config_path)
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    assert!(config_path.exists());
    let contents = std::fs::read_to_string(&config_path).expect("test assertion should succeed");
    assert!(contents.contains("host ="));
}

#[test]
fn test_main_db_config_example() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let dir = tempdir().expect("test assertion should succeed");
    let config_path = dir.path().join("db-config.toml");

    let output = Command::new(exe)
        .arg("--db-config-example")
        .arg(&config_path)
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    assert!(config_path.exists());
    let contents = std::fs::read_to_string(&config_path).expect("test assertion should succeed");
    assert!(contents.contains("[database]"));
    assert!(contents.contains("type ="));
}

#[test]
fn concurrent_cli_processes_preserve_events_in_shared_rolling_log() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let dir = tempdir().expect("test assertion should succeed");
    let log_path = dir.path().join("shared.jsonl");
    let log_dir = dir.path().join(".shared.jsonl.d");
    let processes = (0..8)
        .map(|_| {
            Command::new(exe)
                .args(["--profile", "safe", "--full", "--logfile"])
                .arg(&log_path)
                .env("CIPHERRUN_LOG_FORMAT", "json")
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("CLI process should start")
        })
        .collect::<Vec<_>>();

    for process in processes {
        assert!(!process.wait_with_output().unwrap().status.success());
    }

    let events = std::fs::read_dir(log_dir)
        .unwrap()
        .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect::<String>();
    assert_eq!(events.matches("\"event_name\":\"cli.failed\"").count(), 8);
}
