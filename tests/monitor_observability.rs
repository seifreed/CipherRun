use cipherrun::monitor::{MonitorConfig, MonitorDaemon};
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

fn capture_logs<T>(operation: impl FnOnce() -> T) -> (T, String) {
    let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_writer(output.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, operation);
    let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    (result, output)
}

#[test]
fn monitor_configuration_and_initialization_failures_are_safe_and_structured() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("monitor.toml");
    std::fs::write(&config_path, "monitor = { secret = \"config-sentinel\"").unwrap();

    let (results, output) = capture_logs(|| {
        let config_result = MonitorConfig::from_file(&config_path);
        let mut config = MonitorConfig::default();
        config.monitor.max_concurrent_scans = 0;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let daemon_result = runtime.block_on(MonitorDaemon::new(config));
        (config_result, daemon_result)
    });

    assert!(results.0.is_err());
    assert!(results.1.is_err());
    let events = output
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);

    assert_eq!(events[0]["level"], "WARN");
    assert_eq!(
        events[0]["fields"]["event_name"],
        "monitor.configuration.load_failed"
    );
    assert_eq!(events[0]["fields"]["error_code"], "configuration_error");
    assert_eq!(events[0]["fields"]["outcome"], "failed");
    assert!(events[0]["fields"]["duration_ms"].is_number());

    assert_eq!(events[1]["level"], "WARN");
    assert_eq!(
        events[1]["fields"]["event_name"],
        "monitor.initialization.failed"
    );
    assert_eq!(events[1]["fields"]["stage"], "configuration_validation");
    assert_eq!(events[1]["fields"]["error_code"], "configuration_error");
    assert_eq!(events[1]["fields"]["outcome"], "failed");
    assert!(events[1]["fields"]["duration_ms"].is_number());

    assert!(!output.contains("config-sentinel"));
    assert!(!output.contains(&config_path.display().to_string()));
}
