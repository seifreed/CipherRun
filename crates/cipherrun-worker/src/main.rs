use cipherrun::{Args, commands::run_worker};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let _logging_guard = init_logging();
    let args = match Args::parse_with_sources() {
        Ok(args) => args,
        Err(_error) => {
            tracing::error!(
                error_type = "cli_arguments",
                "Failed to parse worker configuration"
            );
            return ExitCode::from(2);
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
        Err(_error) => {
            tracing::error!(
                event_name = "worker.failed",
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                error_type = "TlsError",
                outcome = "error",
            );
            ExitCode::from(1)
        }
    }
}

fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json =
        std::env::var("CIPHERRUN_LOG_FORMAT").is_ok_and(|value| value.eq_ignore_ascii_case("json"));
    let (writer, guard) = tracing_appender::non_blocking(std::io::stderr());
    if json {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init();
    }
    guard
}
