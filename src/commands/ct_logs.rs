// CtLogsCommand - Certificate Transparency logs streaming
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{Command, CommandExit};
use crate::{Args, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::info;

/// CtLogsCommand handles Certificate Transparency logs streaming
///
/// This command is responsible for:
/// - Configuring CT log sources and indices
/// - Starting the CT log streamer
/// - Streaming certificates from CT logs
pub struct CtLogsCommand {
    args: Args,
}

impl CtLogsCommand {
    /// Create a new CtLogsCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

fn parse_custom_indices(index_args: &[String]) -> Result<HashMap<String, u64>> {
    let mut custom_indices = HashMap::new();
    for index_str in index_args {
        let Some((source, index_value)) = index_str.split_once('=') else {
            crate::tls_bail!("Invalid --ct-index format: {index_str}. Expected SOURCE=INDEX");
        };
        let source = source.trim();
        if source.is_empty() {
            crate::tls_bail!("Invalid --ct-index source: source cannot be empty");
        }
        let index_value = index_value.trim();
        let index = index_value
            .parse::<u64>()
            .map_err(|_| crate::TlsError::InvalidInput {
                message: format!("Invalid index value for source {source}: {index_value}"),
            })?;
        if custom_indices.insert(source.to_string(), index).is_some() {
            crate::tls_bail!("Duplicate --ct-index source: {source}");
        }
    }
    Ok(custom_indices)
}

#[async_trait]
impl Command for CtLogsCommand {
    async fn execute(&self) -> Result<CommandExit> {
        use crate::ct_logs::{CtConfig, CtStreamer};

        info!("Starting CT logs streaming mode");

        let custom_indices = parse_custom_indices(&self.args.ct_logs.index)?;

        // Build configuration
        let config = CtConfig {
            start_from_beginning: self.args.ct_logs.beginning,
            custom_indices,
            poll_interval: std::time::Duration::from_secs(self.args.ct_logs.poll_interval),
            batch_size: self.args.ct_logs.batch_size,
            json_output: self.args.ct_logs.json,
            silent: self.args.ct_logs.silent,
        };

        // Create and start streamer
        let mut streamer = CtStreamer::new(config).await?;
        streamer.start().await?;

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "CtLogsCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;

    #[test]
    fn test_ct_logs_command_name() {
        let args = Args::default();
        let cmd = CtLogsCommand::new(args);
        assert_eq!(cmd.name(), "CtLogsCommand");
    }

    #[test]
    fn test_parse_custom_indices() {
        let indices =
            parse_custom_indices(&[" google = 123 ".to_string(), "cloudflare=67890".to_string()])
                .expect("indices should parse");

        assert_eq!(indices.get("google"), Some(&123));
        assert_eq!(indices.get("cloudflare"), Some(&67890));
    }

    #[test]
    fn test_parse_custom_indices_rejects_invalid_format() {
        let err = parse_custom_indices(&["google:123".to_string()])
            .expect_err("invalid format should fail");
        assert!(err.to_string().contains("Expected SOURCE=INDEX"));
    }

    #[test]
    fn test_parse_custom_indices_rejects_invalid_value() {
        let err = parse_custom_indices(&["google=abc".to_string()])
            .expect_err("invalid value should fail");
        assert!(err.to_string().contains("Invalid index value"));
    }

    #[test]
    fn test_parse_custom_indices_rejects_duplicate_source() {
        let err = parse_custom_indices(&["google=1".to_string(), "google=2".to_string()])
            .expect_err("duplicate source should fail");

        assert!(err.to_string().contains("Duplicate --ct-index source"));
    }
}
