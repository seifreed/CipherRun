use cipherrun::{Args, logging};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for CapturedOutput {
    type Writer = CapturedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedWriter(self.0.clone())
    }
}

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn initialize_reuses_existing_global_subscriber() {
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private destination path"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("private destination path"))
        }
    }

    let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_writer(output.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("test process should not have a global subscriber yet");

    let guard = logging::initialize(&Args::default())
        .expect("existing host subscriber should keep the application running");
    drop(guard);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let log_dir = directory.path().join("logs");
        std::fs::create_dir(&log_dir).expect("log directory should be created");
        for days_ago in 10..18 {
            let date = (chrono::Utc::now() - chrono::Duration::days(days_ago))
                .format("%Y-%m-%d")
                .to_string();
            std::fs::write(log_dir.join(format!("test.{date}")), b"old log\n")
                .expect("old log entry should be created");
        }
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        std::fs::write(log_dir.join(format!("test.{today}")), b"existing\n")
            .expect("current log should be created");
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o555))
            .expect("log directory should become read-only");
        let _appender = tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("test")
            .max_log_files(7)
            .build(&log_dir)
            .expect("rolling appender should initialize");
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o755))
            .expect("log directory should become writable for cleanup");
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("logging.file_retention.delete_failed"),
            "{output}"
        );
        assert!(output.contains("\"level\":\"WARN\""), "{output}");
        assert!(!output.contains(&directory.path().display().to_string()));
        assert!(!output.contains("Failed to remove old log file"));
    }

    let (non_blocking, worker_guard) =
        tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .finish(FailingWriter);
    let failing_subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(non_blocking)
        .finish();
    tracing::subscriber::with_default(failing_subscriber, || {
        tracing::info!(
            event_name = "test.logging.destination",
            "exercise failing sink"
        );
    });
    drop(worker_guard);

    let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("logging.subscriber.reused"), "{output}");
    assert!(output.contains("existing_subscriber"), "{output}");
    assert!(output.contains("logging.worker.io_failed"), "{output}");
    assert!(!output.contains("private destination path"));
}
