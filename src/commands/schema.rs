use super::{Command, CommandExit};
use crate::Result;
use crate::output::schema::CipherRunSchema;
use async_trait::async_trait;
use std::path::PathBuf;

pub struct SchemaCommand {
    output: Option<PathBuf>,
}

impl SchemaCommand {
    pub fn new(output: Option<PathBuf>) -> Self {
        Self { output }
    }
}

#[async_trait]
impl Command for SchemaCommand {
    async fn execute(&self) -> Result<CommandExit> {
        if let Some(path) = &self.output {
            CipherRunSchema::export_schema(path.to_str().ok_or_else(|| {
                crate::TlsError::InvalidInput {
                    message: "Schema output path must be valid UTF-8".to_string(),
                }
            })?)?;
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&CipherRunSchema::get_schema())?
            );
        }

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "SchemaCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn exports_schema_to_file() {
        let directory = tempdir().expect("temporary directory should be created");
        let path = directory.path().join("scan-results.schema.json");

        SchemaCommand::new(Some(path.clone()))
            .execute()
            .await
            .expect("schema export should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("schema should exist"))
                .expect("schema should be valid JSON");
        assert_eq!(value["properties"]["schema_version"]["const"], "1.1");
        assert_eq!(value["title"], "CipherRun Scan Results");
    }
}
