// Standalone database-backed scan worker.

use super::{Command, CommandExit};
use crate::{Args, Result, TlsError};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{info, warn};

/// Processes jobs from the shared SQL queue without starting an HTTP server.
pub struct WorkerCommand {
    args: Args,
}

impl WorkerCommand {
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

/// Run the standalone database-backed worker with explicit API and database
/// configuration. The dedicated worker crate delegates to this function so
/// queue, lease, retry, and webhook behavior remain single-sourced.
pub async fn run_worker(args: &Args) -> Result<()> {
    let api_config_path =
        args.api_server
            .config
            .as_deref()
            .ok_or_else(|| {
                TlsError::ConfigError {
            message:
                "--worker requires --api-config so worker limits and webhook settings are explicit"
                    .to_string(),
        }
            })?;
    let db_config_path = args
        .database
        .config
        .as_deref()
        .ok_or_else(|| TlsError::ConfigError {
            message: "--worker requires --db-config for a shared SQL job queue".to_string(),
        })?;

    let api_config = crate::api::ApiConfig::from_file(api_config_path)?;
    let database_config = crate::db::DatabaseConfig::from_file(db_config_path)?;
    let pool = Arc::new(crate::db::DatabasePool::new(&database_config.database).await?);
    crate::db::run_migrations(pool.as_ref()).await?;

    let queue = crate::api::jobs::DatabaseJobQueue::new(
        pool,
        api_config.job_queue_capacity,
        Some(chrono::Duration::seconds(
            i64::try_from(api_config.job_retention_seconds).map_err(|_| TlsError::ConfigError {
                message: "job_retention_seconds exceeds the supported range".to_string(),
            })?,
        )),
    );
    let executor = Arc::new(
        crate::api::jobs::ScanExecutor::new(queue, api_config.max_concurrent_scans)
            .with_webhook_signing_secret(api_config.webhook_signing_secret()?)
            .with_worker_allowed_cidrs(api_config.worker_allowed_cidrs.clone()),
    );

    if api_config.local_executor {
        warn!(
            "worker started with local_executor=true; disable it on the API server only when external workers should own all queue execution"
        );
    }
    info!(
        database = %db_config_path.display(),
        concurrency = api_config.max_concurrent_scans,
        "Starting standalone scan worker"
    );

    let runner = Arc::clone(&executor);
    let mut handle = tokio::spawn(async move { runner.start().await });
    tokio::select! {
        result = &mut handle => {
            result.map_err(|error| TlsError::Other(format!("worker task failed: {error}")))??;
        }
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|error| TlsError::Other(format!("worker signal handler failed: {error}")))?;
            executor.shutdown().await?;
            handle.await.map_err(|error| TlsError::Other(format!("worker shutdown failed: {error}")))??;
        }
    }

    Ok(())
}

#[async_trait]
impl Command for WorkerCommand {
    async fn execute(&self) -> Result<CommandExit> {
        run_worker(&self.args).await?;
        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "WorkerCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_command_name_is_stable() {
        assert_eq!(WorkerCommand::new(Args::default()).name(), "WorkerCommand");
    }
}
