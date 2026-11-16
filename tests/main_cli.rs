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
fn starttls_only_failures_have_operation_specific_events() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let output = Command::new(exe)
        .args(["--starttls-only", "--starttls-smtp"])
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("binary should run");

    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "failed operation should not emit results"
    );
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("stderr events should be JSON"))
        .collect();
    let failed = events
        .iter()
        .find(|event| event["fields"]["event_name"] == "cli.starttls_only.failed")
        .expect("STARTTLS-only failure should have an operation event");
    assert_eq!(failed["level"], "ERROR");
    assert_eq!(failed["fields"]["operation"], "starttls_only");
    assert_eq!(failed["fields"]["error_type"], "TlsError");
    assert_eq!(failed["fields"]["outcome"], "error");
    assert!(failed["fields"]["duration_ms"].is_number());
    assert!(
        !stderr.contains("cli.failed"),
        "failure must not be logged twice"
    );
}

#[test]
#[cfg(unix)]
fn rolling_file_startup_fallback_redacts_paths_and_os_errors() {
    use std::os::unix::fs::PermissionsExt;

    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let directory = tempdir().expect("temporary directory should be created");
    let log_path = directory.path().join("diagnostics.jsonl");
    let log_dir = directory.path().join(".diagnostics.jsonl.d");
    std::fs::create_dir(&log_dir).expect("log directory should be created");
    for days_ago in 10..18 {
        let date = (chrono::Utc::now() - chrono::Duration::days(days_ago))
            .format("%Y-%m-%d")
            .to_string();
        std::fs::write(
            log_dir.join(format!("diagnostics.jsonl.{date}")),
            b"old log\n",
        )
        .expect("old log entry should be created");
    }
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    std::fs::write(
        log_dir.join(format!("diagnostics.jsonl.{today}")),
        b"existing\n",
    )
    .expect("current log should be created");
    std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o555))
        .expect("log directory should become read-only");

    let output = Command::new(exe)
        .args(["--version", "--logfile"])
        .arg(&log_path)
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o755))
        .expect("log directory should become writable for cleanup");
    let sanitized_stderr = stderr.replace(
        &directory.path().display().to_string(),
        "<temporary-log-directory>",
    );
    assert!(
        sanitized_stderr.contains("logging.file_retention.delete_failed"),
        "{sanitized_stderr}"
    );
    assert!(!stderr.contains(&directory.path().display().to_string()));
    assert!(!stderr.contains("Failed to remove old log file"));
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
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    assert!(config_path.exists());
    let contents = std::fs::read_to_string(&config_path).expect("test assertion should succeed");
    assert!(contents.contains("host ="));
    let token_path = config_path.with_extension("token");
    let token = std::fs::read_to_string(token_path).expect("bootstrap token should be written");
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("stderr events should be JSON"))
        .collect();
    let completed = events
        .iter()
        .find(|event| {
            event["fields"]["event_name"] == "cli.operation.completed"
                && event["fields"]["operation"] == "create_api_config_example"
        })
        .expect("API config generation should have a completion event");
    assert_eq!(completed["level"], "INFO");
    assert!(completed["fields"]["duration_ms"].is_number());
    assert!(!stderr.contains(&dir.path().display().to_string()));
    assert!(!stderr.contains(&token));
}

#[test]
fn test_main_db_config_example() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let dir = tempdir().expect("test assertion should succeed");
    let config_path = dir.path().join("db-config.toml");

    let output = Command::new(exe)
        .arg("--db-config-example")
        .arg(&config_path)
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
    assert!(config_path.exists());
    let contents = std::fs::read_to_string(&config_path).expect("test assertion should succeed");
    assert!(contents.contains("[database]"));
    assert!(contents.contains("type ="));
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("stderr events should be JSON"))
        .collect();
    let completed = events
        .iter()
        .find(|event| {
            event["fields"]["event_name"] == "cli.operation.completed"
                && event["fields"]["operation"] == "create_database_config_example"
        })
        .expect("database config generation should have a completion event");
    assert_eq!(completed["level"], "INFO");
    assert!(completed["fields"]["duration_ms"].is_number());
    assert!(!stderr.contains(&dir.path().display().to_string()));
    assert!(!stderr.contains("secure_password"));
}

#[test]
fn api_config_example_write_failure_is_logged_once_without_paths_or_secrets() {
    let exe = env!("CARGO_BIN_EXE_cipherrun");
    let directory = tempdir().expect("temporary directory should be created");
    let config_path = directory.path().join("api-config.toml");
    std::fs::write(&config_path, "existing credentials")
        .expect("existing config should be written");

    let output = Command::new(exe)
        .arg("--api-config-example")
        .arg(&config_path)
        .env("CIPHERRUN_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .output()
        .expect("binary should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("diagnostics should be UTF-8");
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("stderr events should be JSON"))
        .collect();
    let failed = events
        .iter()
        .find(|event| {
            event["fields"]["event_name"] == "cli.operation.failed"
                && event["fields"]["operation"] == "create_api_config_example"
        })
        .expect("API config write failure should have an operation event");
    assert_eq!(failed["level"], "ERROR");
    assert_eq!(failed["fields"]["outcome"], "error");
    assert!(failed["fields"]["error_code"].is_string());
    assert!(failed["fields"]["duration_ms"].is_number());
    assert_eq!(
        events
            .iter()
            .filter(|event| event["fields"]["event_name"] == "cli.operation.failed")
            .count(),
        1
    );
    assert!(!stderr.contains("cli.failed"));
    assert!(!stderr.contains(&directory.path().display().to_string()));
    assert!(!stderr.contains("bootstrap-admin"));
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
