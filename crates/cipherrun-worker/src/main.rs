use cipherrun::{Args, commands::run_worker as execute_worker};
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
    let logging_result = cipherrun::logging::initialize(&args);
    run_after_logging_initialization(args, logging_result).await
}

async fn run_after_logging_initialization(
    args: Args,
    logging_result: cipherrun::Result<cipherrun::logging::LoggingGuard>,
) -> ExitCode {
    let _logging_guard = match logging_result {
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
    let result = execute_worker(&args).await;
    finish_worker(result, started.elapsed())
}

fn finish_worker(result: cipherrun::Result<()>, duration: std::time::Duration) -> ExitCode {
    let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    match result {
        Ok(()) => {
            let event_name = "worker.finished";
            let outcome = "complete";
            tracing::info!(event_name, duration_ms, outcome);
            ExitCode::SUCCESS
        }
        Err(error) => {
            let event_name = "worker.failed";
            let error_type = "TlsError";
            let error_code = error.observability_code();
            let outcome = "error";
            tracing::error!(event_name, duration_ms, error_type, error_code, outcome);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedOutputWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedOutputWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedOutputWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedOutputWriter(self.0.clone())
        }
    }

    #[tokio::test]
    async fn logging_initialization_failure_returns_nonzero_exit() {
        let args = Args::parse_with_sources_from(["cipherrun-worker", "--worker"])
            .expect("worker arguments should parse");
        let exit = run_after_logging_initialization(
            args,
            Err(cipherrun::TlsError::Other(
                "subscriber setup failed".to_string(),
            )),
        )
        .await;

        assert_eq!(exit, ExitCode::from(1));
    }

    #[test]
    fn successful_worker_completion_is_structured() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();

        let exit = tracing::subscriber::with_default(subscriber, || {
            finish_worker(Ok(()), std::time::Duration::from_millis(7))
        });
        CapturedOutputWriter(output.clone())
            .flush()
            .expect("test writer flush should succeed");

        assert_eq!(exit, ExitCode::SUCCESS);
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["event_name"], "worker.finished");
        assert_eq!(event["fields"]["duration_ms"], 7);
        assert_eq!(event["fields"]["outcome"], "complete");
    }

    #[test]
    fn worker_duration_saturates_when_milliseconds_exceed_u64() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();

        let exit = tracing::subscriber::with_default(subscriber, || {
            finish_worker(Ok(()), std::time::Duration::MAX)
        });

        assert_eq!(exit, ExitCode::SUCCESS);
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["duration_ms"], u64::MAX);
    }

    #[test]
    fn worker_failure_is_structured_and_redacted() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();

        let exit = tracing::subscriber::with_default(subscriber, || {
            finish_worker(
                Err(cipherrun::TlsError::Other("failure".to_string())),
                std::time::Duration::from_millis(12),
            )
        });

        assert_eq!(exit, ExitCode::from(1));
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["event_name"], "worker.failed");
        assert_eq!(event["fields"]["duration_ms"], 12);
        assert_eq!(event["fields"]["error_code"], "other");
        assert_eq!(event["fields"]["outcome"], "error");
        assert!(!output.contains("failure"));
    }
}
