use super::{Command, CommandExit};
use crate::output::schema::CipherRunSchema;
use crate::scanner::{ScanResults, diff::ScanDiff};
use crate::{Result, TlsError};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

const MAX_SCAN_RESULT_BYTES: u64 = 64 * 1024 * 1024;

pub struct ScanDiffCommand {
    previous: PathBuf,
    current: PathBuf,
    json: bool,
}

impl ScanDiffCommand {
    pub fn new(previous: PathBuf, current: PathBuf, json: bool) -> Self {
        Self {
            previous,
            current,
            json,
        }
    }

    pub(crate) fn read_scan(path: &Path) -> Result<ScanResults> {
        let size = std::fs::metadata(path)?.len();
        if size > MAX_SCAN_RESULT_BYTES {
            return Err(TlsError::InvalidInput {
                message: format!(
                    "Scan result {} is too large: {} bytes (max {})",
                    path.display(),
                    size,
                    MAX_SCAN_RESULT_BYTES
                ),
            });
        }
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        CipherRunSchema::validate(&value).map_err(|errors| TlsError::InvalidInput {
            message: format!(
                "Invalid CipherRun scan result {}: {}",
                path.display(),
                errors.join("; ")
            ),
        })?;
        Ok(serde_json::from_value(value)?)
    }
}

#[async_trait]
impl Command for ScanDiffCommand {
    async fn execute(&self) -> Result<CommandExit> {
        let previous = Self::read_scan(&self.previous)?;
        let current = Self::read_scan(&self.current)?;
        let diff = ScanDiff::compare(&previous, &current)?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&diff)?);
        } else {
            println!("{}", diff.to_terminal());
        }

        if diff.has_changes() {
            Ok(CommandExit::drift_failure())
        } else {
            Ok(CommandExit::success())
        }
    }

    fn name(&self) -> &'static str {
        "ScanDiffCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use tempfile::tempdir;

    #[test]
    fn reads_versioned_scan_fixture() {
        let scan = ScanDiffCommand::read_scan(Path::new(
            "fixtures/scan-results/1.1-potential-exposure.json",
        ))
        .unwrap();
        assert_eq!(scan.scan_metadata.schema_version, "1.1");
    }

    #[test]
    fn rejects_oversized_scan_before_reading() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("oversized.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_SCAN_RESULT_BYTES + 1).unwrap();

        let error = ScanDiffCommand::read_scan(&path).unwrap_err();
        assert!(error.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn returns_drift_exit_for_changed_scan() {
        let directory = tempdir().unwrap();
        let previous_path = directory.path().join("previous.json");
        let current_path = directory.path().join("current.json");
        let previous = ScanResults {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        let current = ScanResults {
            target: previous.target.clone(),
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS13,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            ..Default::default()
        };
        std::fs::write(&previous_path, previous.to_json(false).unwrap()).unwrap();
        std::fs::write(&current_path, current.to_json(false).unwrap()).unwrap();

        let exit = ScanDiffCommand::new(previous_path, current_path, true)
            .execute()
            .await
            .unwrap();
        assert_eq!(exit.code(), CommandExit::DRIFT_FAILURE);
    }
}
