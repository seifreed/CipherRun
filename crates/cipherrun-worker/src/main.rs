use cipherrun::{Args, commands::run_worker};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args = match Args::parse_with_sources() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::from(2);
        }
    };

    match run_worker(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(1)
        }
    }
}
