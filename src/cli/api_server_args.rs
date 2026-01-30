// REST API server configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;
use std::path::PathBuf;

/// REST API server configuration
///
/// This struct contains all arguments related to the REST API server mode,
/// including host/port binding, concurrency limits, and OpenAPI/Swagger UI.
#[derive(Args, Debug, Clone, Default)]
pub struct ApiServerArgs {
    /// Start REST API server mode
    #[arg(long = "serve", id = "api_enable")]
    pub enable: bool,

    /// API server host address
    #[arg(
        long = "api-host",
        value_name = "HOST",
        default_value = "0.0.0.0",
        id = "api_host"
    )]
    pub host: String,

    /// API server port
    #[arg(
        long = "api-port",
        value_name = "PORT",
        default_value = "8080",
        id = "api_port"
    )]
    pub port: u16,

    /// API configuration file (TOML format)
    #[arg(long = "api-config", value_name = "FILE", id = "api_config")]
    pub config: Option<PathBuf>,

    /// Maximum concurrent scans
    #[arg(long = "api-max-concurrent", value_name = "NUM", default_value = "10")]
    pub max_concurrent: usize,

    /// Enable Swagger UI documentation
    #[arg(long = "api-swagger")]
    pub swagger: bool,

    /// Generate example API configuration file
    #[arg(
        long = "api-config-example",
        value_name = "FILE",
        id = "api_config_example"
    )]
    pub config_example: Option<PathBuf>,
}
