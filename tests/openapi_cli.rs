use std::process::Command;

#[test]
fn openapi_binary_writes_valid_schema_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_cipherrun-openapi"))
        .output()
        .expect("OpenAPI binary should start");

    assert!(output.status.success());
    let schema: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("binary should write valid JSON");
    assert!(schema["openapi"].is_string());
    assert!(schema["paths"].is_object());
}
