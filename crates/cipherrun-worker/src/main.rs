use cipherrun::{Args, commands::run_worker};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    cipherrun::logging::install_safe_panic_hook();
    let args = match Args::parse_with_sources() {
        Ok(args) => args,
        Err(_) => {
            eprintln!("Failed to parse worker configuration (error_code=configuration_error)");
            return ExitCode::from(2);
        }
    };
    let _logging_guard = match logging_guard_or_exit(cipherrun::logging::initialize(&args)) {
        Ok(guard) => guard,
        Err(exit_code) => return exit_code,
    };

    let started = std::time::Instant::now();
    match run_worker(&args).await {
        Ok(()) => {
            tracing::info!(
                event_name = "worker.finished",
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                outcome = "complete",
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(
                event_name = "worker.failed",
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                error_type = "TlsError",
                error_code = error.observability_code(),
                outcome = "error",
            );
            ExitCode::from(1)
        }
    }
}

fn logging_guard_or_exit(
    result: cipherrun::Result<cipherrun::logging::LoggingGuard>,
) -> Result<cipherrun::logging::LoggingGuard, ExitCode> {
    result.map_err(|error| {
        eprintln!(
            "Failed to initialize worker logging (error_code={})",
            error.observability_code()
        );
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_initialization_failure_returns_nonzero_exit() {
        let result = logging_guard_or_exit(Err(cipherrun::TlsError::Other(
            "subscriber setup failed".to_string(),
        )));

        assert!(matches!(result, Err(code) if code == ExitCode::from(1)));
    }
}
