use std::process::Command;
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
