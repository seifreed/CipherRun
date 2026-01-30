// ApiServerCommand - REST API server mode
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::Command;
use crate::{Args, Result, TlsError};
use async_trait::async_trait;
use tracing::info;

/// ApiServerCommand handles REST API server mode
///
/// This command is responsible for:
/// - Loading API configuration from file or CLI arguments
/// - Creating and configuring the API server
/// - Starting the server and handling requests
pub struct ApiServerCommand {
    args: Args,
}

impl ApiServerCommand {
    /// Create a new ApiServerCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

#[async_trait]
impl Command for ApiServerCommand {
    async fn execute(&self) -> Result<()> {
        use crate::api::{ApiConfig, ApiServer};

        info!("Starting CipherRun in API server mode");

        // Load configuration from file or use CLI args
        let mut config = if let Some(config_path) = &self.args.api_server.config {
            let config_str = config_path.to_str().ok_or_else(|| TlsError::InvalidInput {
                message: "Invalid config file path".to_string(),
            })?;
            ApiConfig::from_file(config_str)?
        } else {
            ApiConfig::default()
        };

        // Override with CLI arguments
        config.host = self.args.api_server.host.clone();
        config.port = self.args.api_server.port;
        config.max_concurrent_scans = self.args.api_server.max_concurrent;
        config.enable_swagger = self.args.api_server.swagger || config.enable_swagger;

        // Create and run server
        let server = ApiServer::new(config)?;
        server.run().await?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ApiServerCommand"
    }
}
