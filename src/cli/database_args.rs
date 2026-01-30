// Database configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;
use std::path::PathBuf;

/// Database persistence and history configuration
///
/// This struct contains all arguments related to database operations,
/// including configuration, storage, history queries, and maintenance.
#[derive(Args, Debug, Clone, Default)]
pub struct DatabaseArgs {
    /// Database configuration file (TOML format)
    #[arg(long = "db-config", value_name = "FILE", id = "db_config")]
    pub config: Option<PathBuf>,

    /// Store scan results in database
    #[arg(long = "store")]
    pub store_results: bool,

    /// Query scan history for target (hostname:port)
    #[arg(long = "history", value_name = "HOSTNAME:PORT")]
    pub history: Option<String>,

    /// Limit for history results
    #[arg(long = "history-limit", value_name = "COUNT", default_value = "10")]
    pub history_limit: i64,

    /// Cleanup old scans (delete scans older than N days)
    #[arg(long = "cleanup-days", value_name = "DAYS")]
    pub cleanup_days: Option<i64>,

    /// Initialize database (create tables and run migrations)
    #[arg(long = "db-init")]
    pub init: bool,

    /// Generate example database configuration file
    #[arg(
        long = "db-config-example",
        value_name = "FILE",
        id = "db_config_example"
    )]
    pub config_example: Option<PathBuf>,
}
