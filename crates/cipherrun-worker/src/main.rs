use cipherrun::{Args, commands::run_worker};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args = match Args::parse_with_sources() {
        Ok(args) => args,
        Err(_) => {
            eprintln!("Failed to parse worker configuration (error_code=configuration_error)");
            return ExitCode::from(2);
        }
    };
    let _logging_guard = match cipherrun::logging::initialize(&args) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!(
                "Failed to initialize worker logging (error_code={})",
                error.observability_code()
            );
            return ExitCode::from(1);
        }
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
