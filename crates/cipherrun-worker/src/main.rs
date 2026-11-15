use cipherrun::{Args, commands::run_worker};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    let args = match Args::parse_with_sources() {
        Ok(args) => args,
        Err(error) => {
            tracing::error!(error = %error, "Failed to parse worker configuration");
            return ExitCode::from(2);
        }
    };

    match run_worker(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "Worker terminated with an error");
            ExitCode::from(1)
        }
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
