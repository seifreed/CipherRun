// CtLogsCommand - Certificate Transparency logs streaming
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
use crate::{Args, Result};
use async_trait::async_trait;
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

#[async_trait]
impl Command for CtLogsCommand {
    async fn execute(&self) -> Result<()> {
        use crate::ct_logs::{CtConfig, CtStreamer};
        use std::collections::HashMap;

        info!("Starting CT logs streaming mode");

        // Parse custom indices from CLI arguments
        let mut custom_indices = HashMap::new();
        for index_str in &self.args.ct_logs.index {
            let parts: Vec<&str> = index_str.split('=').collect();
            if parts.len() == 2 {
                if let Ok(index) = parts[1].parse::<u64>() {
                    custom_indices.insert(parts[0].to_string(), index);
                } else {
                    eprintln!(
                        "Warning: Invalid index value for source {}: {}",
                        parts[0], parts[1]
                    );
                }
            } else {
                eprintln!(
                    "Warning: Invalid --ct-index format: {}. Expected SOURCE=INDEX",
                    index_str
                );
            }
        }

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

        Ok(())
    }

    fn name(&self) -> &'static str {
        "CtLogsCommand"
    }
}
