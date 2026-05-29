// ApiServerCommand - REST API server mode
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::{Command, CommandExit};
use crate::{Args, Result, TlsError};
use async_trait::async_trait;
use tracing::info;

/// Default bind address when neither a config file nor `--api-host` is given.
const DEFAULT_API_HOST: &str = "0.0.0.0";
/// Default port when neither a config file nor `--api-port` is given.
const DEFAULT_API_PORT: u16 = 8080;
/// Default concurrency when neither a config file nor `--api-max-concurrent` is given.
const DEFAULT_API_MAX_CONCURRENT: usize = 10;

/// Apply CLI arguments on top of a loaded API config.
///
/// CLI flags override the config file, but only when the user actually
/// supplied them; otherwise the clap defaults would silently clobber the
/// host/port/concurrency read from `--api-config`. When no config file was
/// loaded, fall back to the documented CLI defaults so the common `--serve`
/// invocation behaves unchanged.
fn apply_cli_overrides(
    config: &mut crate::api::ApiConfig,
    args: &crate::cli::ApiServerArgs,
    has_config_file: bool,
) {
    if let Some(host) = &args.host {
        config.host = host.clone();
    } else if !has_config_file {
        config.host = DEFAULT_API_HOST.to_string();
    }
    if let Some(port) = args.port {
        config.port = port;
    } else if !has_config_file {
        config.port = DEFAULT_API_PORT;
    }
    if let Some(max_concurrent) = args.max_concurrent {
        config.max_concurrent_scans = max_concurrent;
    } else if !has_config_file {
        config.max_concurrent_scans = DEFAULT_API_MAX_CONCURRENT;
    }
    config.enable_swagger = args.swagger || config.enable_swagger;
}

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
    async fn execute(&self) -> Result<CommandExit> {
        use crate::api::{ApiConfig, ApiServer};

        info!("Starting CipherRun in API server mode");

        // Load configuration from file or use CLI args
        let has_config_file = self.args.api_server.config.is_some();
        let mut config = if let Some(config_path) = &self.args.api_server.config {
            let config_str = config_path.to_str().ok_or_else(|| TlsError::InvalidInput {
                message: "Invalid config file path".to_string(),
            })?;
            ApiConfig::from_file(config_str)?
        } else {
            ApiConfig::default()
        };

        apply_cli_overrides(&mut config, &self.args.api_server, has_config_file);

        // Create and run server
        let server = ApiServer::new(config)?;
        server.run().await?;

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "ApiServerCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;

    #[test]
    fn test_api_server_command_name() {
        let args = Args::default();
        let cmd = ApiServerCommand::new(args);
        assert_eq!(cmd.name(), "ApiServerCommand");
    }

    #[test]
    fn test_config_file_host_port_preserved_when_no_cli_flags() {
        let mut config = crate::api::ApiConfig {
            host: "192.168.1.5".to_string(),
            port: 18090,
            max_concurrent_scans: 3,
            ..crate::api::ApiConfig::default()
        };

        // No CLI flags => config-file values must survive (regression: clap
        // defaults used to overwrite them with 0.0.0.0:8080).
        let args = crate::cli::ApiServerArgs::default();
        apply_cli_overrides(&mut config, &args, true);

        assert_eq!(config.host, "192.168.1.5");
        assert_eq!(config.port, 18090);
        assert_eq!(config.max_concurrent_scans, 3);
    }

    #[test]
    fn test_cli_flags_override_config_file() {
        let mut config = crate::api::ApiConfig {
            host: "192.168.1.5".to_string(),
            port: 18090,
            ..crate::api::ApiConfig::default()
        };

        let args = crate::cli::ApiServerArgs {
            host: Some("10.0.0.1".to_string()),
            port: Some(9999),
            ..Default::default()
        };
        apply_cli_overrides(&mut config, &args, true);

        assert_eq!(config.host, "10.0.0.1");
        assert_eq!(config.port, 9999);
    }

    #[test]
    fn test_no_config_no_flags_uses_documented_defaults() {
        let mut config = crate::api::ApiConfig::default();
        let args = crate::cli::ApiServerArgs::default();
        apply_cli_overrides(&mut config, &args, false);

        assert_eq!(config.host, DEFAULT_API_HOST);
        assert_eq!(config.port, DEFAULT_API_PORT);
        assert_eq!(config.max_concurrent_scans, DEFAULT_API_MAX_CONCURRENT);
    }
}
