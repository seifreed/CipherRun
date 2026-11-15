use crate::{Args, Result, TlsError};
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{self, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
#[cfg(not(feature = "otel"))]
use tracing_subscriber::FmtSubscriber;

pub fn initialize(args: &Args) -> Result<LoggingGuard> {
    let filter = resolve_log_filter(
        std::env::var("RUST_LOG").ok().as_deref(),
        args.output.verbose,
    );
    let json = json_logs_enabled(std::env::var("CIPHERRUN_LOG_FORMAT").ok().as_deref());
    let file = args.output.logfile.as_ref().and_then(|path| {
        rolling_log_file(path).map_or_else(
            |_| {
                report_log_file_fallback(json);
                None
            },
            Some,
        )
    });
    let (writer, writer_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .finish(LogWriter { file });
    let dropped_log_lines = writer.error_counter();

    #[cfg(feature = "otel")]
    let tracer_provider = {
        use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

        let fmt_layer = if json {
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer)
                .with_filter(filter)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_filter(filter)
                .boxed()
        };
        let (otel_layer, provider) = crate::telemetry::layer()?;
        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(otel_layer)
            .try_init()
            .map_err(|_| TlsError::Other("Failed to set tracing subscriber".to_string()))?;
        Some(provider)
    };

    #[cfg(not(feature = "otel"))]
    {
        let result = if json {
            FmtSubscriber::builder()
                .json()
                .with_env_filter(filter)
                .with_writer(writer)
                .try_init()
        } else {
            FmtSubscriber::builder()
                .with_env_filter(filter)
                .with_writer(writer)
                .try_init()
        };
        result.map_err(|_| TlsError::Other("Failed to set tracing subscriber".to_string()))?;
    }

    let drop_monitor = start_drop_monitor(dropped_log_lines.clone(), json);
    Ok(LoggingGuard {
        writer_guard: Some(writer_guard),
        dropped_log_lines,
        json,
        drop_monitor,
        #[cfg(feature = "otel")]
        tracer_provider,
    })
}

pub struct LoggingGuard {
    writer_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    dropped_log_lines: tracing_appender::non_blocking::ErrorCounter,
    json: bool,
    drop_monitor: Option<(SyncSender<()>, JoinHandle<usize>)>,
    #[cfg(feature = "otel")]
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = &self.tracer_provider
            && provider.shutdown().is_err()
        {
            tracing::warn!(
                event_name = "telemetry.flush.failed",
                "Failed to flush OpenTelemetry spans during shutdown"
            );
        }

        drop(self.writer_guard.take());
        if let Some((stop, monitor)) = self.drop_monitor.take() {
            let _ = stop.send(());
            let already_reported = monitor.join().unwrap_or(0);
            report_dropped_log_lines(
                self.dropped_log_lines
                    .dropped_lines()
                    .saturating_sub(already_reported),
                self.json,
            );
        } else {
            report_dropped_log_lines(self.dropped_log_lines.dropped_lines(), self.json);
        }
    }
}

struct LogWriter {
    file: Option<RollingFileAppender>,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stderr = io::stderr().lock();
        let file = self.file.as_mut().map(|file| file as &mut dyn Write);
        write_to_destinations(buf, &mut stderr, file)
    }

    fn flush(&mut self) -> io::Result<()> {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        let stderr_result = stderr.flush();
        let file_result = self.file.as_mut().map(Write::flush);
        stderr_result?;
        file_result.unwrap_or(Ok(()))
    }
}

fn write_to_destinations(
    buf: &[u8],
    stderr: &mut dyn Write,
    file: Option<&mut dyn Write>,
) -> io::Result<usize> {
    let stderr_result = stderr.write_all(buf);
    let file_result = file.map(|file| file.write_all(buf));
    stderr_result?;
    if let Some(result) = file_result {
        result?;
    }
    Ok(buf.len())
}

fn rolling_log_file(path: &Path) -> io::Result<RollingFileAppender> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Log file path must include a filename",
        )
    })?;
    let name = name.to_string_lossy().into_owned();
    let directory = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{name}.d"));

    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(name)
        .max_log_files(7)
        .build(directory)
        .map_err(io::Error::other)
}

fn resolve_log_filter(rust_log: Option<&str>, verbose: u8) -> EnvFilter {
    rust_log
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| {
            EnvFilter::new(match verbose {
                0 => "info",
                1 => "debug",
                _ => "trace",
            })
        })
}

fn json_logs_enabled(format: Option<&str>) -> bool {
    format.is_some_and(|value| value.eq_ignore_ascii_case("json"))
}

fn start_drop_monitor(
    dropped_log_lines: tracing_appender::non_blocking::ErrorCounter,
    json: bool,
) -> Option<(SyncSender<()>, JoinHandle<usize>)> {
    let (stop, shutdown) = mpsc::sync_channel(1);
    let monitor = std::thread::Builder::new()
        .name("cipherrun-log-drop-monitor".to_string())
        .spawn(move || {
            monitor_dropped_log_lines(
                || dropped_log_lines.dropped_lines(),
                shutdown,
                Duration::from_secs(30),
                |delta| report_dropped_log_lines(delta, json),
            )
        })
        .ok()?;
    Some((stop, monitor))
}

fn monitor_dropped_log_lines(
    mut dropped_lines: impl FnMut() -> usize,
    shutdown: mpsc::Receiver<()>,
    interval: Duration,
    mut report: impl FnMut(usize),
) -> usize {
    let mut reported = 0;
    loop {
        let stopping = matches!(
            shutdown.recv_timeout(interval),
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected)
        );
        let current = dropped_lines();
        let delta = current.saturating_sub(reported);
        report(delta);
        reported = current;
        if stopping {
            return reported;
        }
    }
}

fn report_dropped_log_lines(dropped_lines: usize, json: bool) {
    if dropped_lines > 0 {
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let line = format_dropped_log_event(dropped_lines, json, &timestamp);
        let _ = writeln!(io::stderr().lock(), "{line}");
    }
}

fn report_log_file_fallback(json: bool) {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let line = format_log_file_fallback_event(json, &timestamp);
    let _ = writeln!(io::stderr().lock(), "{line}");
}

fn format_log_file_fallback_event(json: bool, timestamp: &str) -> String {
    if json {
        serde_json::json!({
            "timestamp": timestamp,
            "level": "WARN",
            "fields": {
                "event_name": "logging.file_destination.failed",
                "operation": "open_log_file",
                "error_type": "file_destination",
                "error_code": "filesystem_error",
                "outcome": "stderr_only",
                "message": "Log file unavailable; continuing with stderr"
            },
            "target": "cipherrun::logging"
        })
        .to_string()
    } else {
        "WARN logging.file_destination.failed operation=open_log_file error_type=file_destination error_code=filesystem_error outcome=stderr_only Log file unavailable; continuing with stderr".to_string()
    }
}

fn format_dropped_log_event(dropped_lines: usize, json: bool, timestamp: &str) -> String {
    if json {
        serde_json::json!({
            "timestamp": timestamp,
            "level": "WARN",
            "fields": {
                "event_name": "logging.events_dropped",
                "dropped_lines": dropped_lines,
                "message": "Log events were dropped by the bounded logging queue"
            },
            "target": "cipherrun::logging"
        })
        .to_string()
    } else {
        format!(
            "WARN logging.events_dropped dropped_lines={dropped_lines} Log events were dropped by the bounded logging queue"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LogWriter, format_dropped_log_event, format_log_file_fallback_event, json_logs_enabled,
        monitor_dropped_log_lines, resolve_log_filter, rolling_log_file, write_to_destinations,
    };
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    struct GatedWriter {
        started: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        blocked: bool,
    }

    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter(self.0.clone())
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for GatedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.blocked {
                self.blocked = true;
                let _ = self.started.send(());
                let _ = self.release.recv();
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "simulated destination failure",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "simulated destination failure",
            ))
        }
    }

    #[test]
    fn stderr_failure_does_not_skip_the_file_destination() {
        let file_output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let mut file = BufferWriter(file_output.0.clone());

        let error = write_to_destinations(b"event\n", &mut FailingWriter, Some(&mut file))
            .expect_err("stderr failure should remain observable");

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(*file_output.0.lock().unwrap(), b"event\n");
    }

    #[test]
    fn file_failure_does_not_skip_stderr_destination() {
        let stderr_output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let mut stderr = BufferWriter(stderr_output.0.clone());

        let error = write_to_destinations(b"event\n", &mut stderr, Some(&mut FailingWriter))
            .expect_err("file failure should remain observable");

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(*stderr_output.0.lock().unwrap(), b"event\n");
    }

    #[test]
    fn filter_defaults_to_info_and_uses_verbosity() {
        assert!(resolve_log_filter(None, 0).to_string().contains("info"));
        assert!(resolve_log_filter(None, 1).to_string().contains("debug"));
        assert!(resolve_log_filter(None, 2).to_string().contains("trace"));
    }

    #[test]
    fn filter_honors_module_directives_and_falls_back_when_invalid() {
        assert!(
            resolve_log_filter(Some("warn,cipherrun::api=debug"), 0)
                .to_string()
                .contains("cipherrun::api=debug")
        );
        assert!(
            resolve_log_filter(Some("cipherrun=not-a-level"), 1)
                .to_string()
                .contains("debug")
        );
    }

    #[test]
    fn json_format_is_opt_in_and_case_insensitive() {
        assert!(json_logs_enabled(Some("json")));
        assert!(json_logs_enabled(Some("JSON")));
        assert!(!json_logs_enabled(None));
        assert!(!json_logs_enabled(Some("text")));
    }

    #[test]
    fn json_format_escapes_untrusted_control_characters() {
        let output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();
        let untrusted = "value\nlevel=ERROR\r\u{001b}[2J";

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(input = %untrusted, "test event");
        });

        let bytes = output.0.lock().unwrap().clone();
        let serialized = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(serialized.lines().count(), 1);
        let event: serde_json::Value = serde_json::from_str(serialized).unwrap();
        assert_eq!(event["fields"]["input"], untrusted);
    }

    #[test]
    fn dropped_log_lines_use_a_safe_json_fallback_event() {
        let serialized = format_dropped_log_event(3, true, "2026-11-15T12:00:00.000000Z");
        let event: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event["level"], "WARN");
        assert_eq!(event["fields"]["event_name"], "logging.events_dropped");
        assert_eq!(event["fields"]["dropped_lines"], 3);
        assert_eq!(event["timestamp"], "2026-11-15T12:00:00.000000Z");
    }

    #[test]
    fn failed_file_destination_uses_safe_json_fallback_event() {
        let serialized = format_log_file_fallback_event(true, "2026-11-15T12:00:00.000000Z");
        let event: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event["level"], "WARN");
        assert_eq!(
            event["fields"]["event_name"],
            "logging.file_destination.failed"
        );
        assert_eq!(event["fields"]["error_code"], "filesystem_error");
        assert_eq!(event["fields"]["outcome"], "stderr_only");
        assert!(!serialized.contains("/private/path"));
    }

    #[test]
    fn drop_monitor_reports_new_lines_and_stops_without_waiting_for_interval() {
        let dropped_lines = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        let (reported_tx, reported_rx) = mpsc::channel();
        let monitor_count = dropped_lines.clone();
        let monitor = std::thread::spawn(move || {
            monitor_dropped_log_lines(
                || monitor_count.load(Ordering::SeqCst),
                shutdown_rx,
                Duration::from_millis(10),
                |delta| {
                    if delta > 0 {
                        reported_tx.send(delta).unwrap();
                    }
                },
            )
        });

        dropped_lines.store(4, Ordering::SeqCst);
        assert_eq!(reported_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 4);
        dropped_lines.store(7, Ordering::SeqCst);
        shutdown_tx.send(()).unwrap();
        assert_eq!(reported_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 3);
        assert_eq!(monitor.join().unwrap(), 7);
    }

    #[test]
    fn bounded_queue_counts_events_dropped_while_writer_is_blocked() {
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::channel();
        let (writer, worker_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(1)
            .lossy(true)
            .finish(GatedWriter {
                started: started_tx,
                release: release_rx,
                blocked: false,
            });
        let dropped_lines = writer.error_counter();
        let subscriber = tracing_subscriber::fmt().with_writer(writer).finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(event_name = "logging.queue.first", "first event");
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            tracing::info!(event_name = "logging.queue.second", "second event");
            tracing::info!(
                event_name = "logging.queue.dropped",
                "event under saturation"
            );
            assert!(dropped_lines.dropped_lines() > 0);
        });

        release_tx.send(()).unwrap();
        drop(worker_guard);
        assert!(dropped_lines.dropped_lines() > 0);
    }

    #[test]
    fn bounded_queue_flushes_concurrent_sustained_burst_without_drops() {
        const PRODUCERS: usize = 8;
        const EVENTS_PER_PRODUCER: usize = 1_000;

        let output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let (writer, worker_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(PRODUCERS * EVENTS_PER_PRODUCER)
            .lossy(true)
            .finish(BufferWriter(output.0.clone()));
        let dropped_lines = writer.error_counter();
        let subscriber = tracing_subscriber::fmt().with_writer(writer).finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let producers = (0..PRODUCERS)
            .map(|producer| {
                let dispatch = dispatch.clone();
                std::thread::spawn(move || {
                    tracing::dispatcher::with_default(&dispatch, || {
                        for event in 0..EVENTS_PER_PRODUCER {
                            tracing::info!(
                                event_name = "logging.load_test",
                                producer,
                                event,
                                "concurrent load event"
                            );
                        }
                    });
                })
            })
            .collect::<Vec<_>>();

        for producer in producers {
            producer.join().unwrap();
        }
        drop(dispatch);
        drop(worker_guard);

        assert_eq!(dropped_lines.dropped_lines(), 0);
        let output = output.0.lock().unwrap();
        assert_eq!(
            output.iter().filter(|byte| **byte == b'\n').count(),
            PRODUCERS * EVENTS_PER_PRODUCER
        );
    }

    #[test]
    #[ignore = "manual 30-second rolling-file logging soak"]
    fn rolling_file_writer_accounts_for_sustained_concurrent_logging() {
        const PRODUCERS: usize = 4;
        const SOAK: Duration = Duration::from_secs(30);

        let directory = tempfile::tempdir().unwrap();
        let logfile = directory.path().join("soak.jsonl");
        let file = rolling_log_file(&logfile).unwrap();
        let (writer, worker_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(true)
            .finish(file);
        let dropped_lines = writer.error_counter();
        let (stop_monitor, shutdown) = mpsc::sync_channel(1);
        let (reported_tx, reported_rx) = mpsc::channel();
        let monitor_dropped_lines = dropped_lines.clone();
        let monitor = std::thread::spawn(move || {
            monitor_dropped_log_lines(
                || monitor_dropped_lines.dropped_lines(),
                shutdown,
                Duration::from_secs(30),
                |delta| {
                    if delta > 0 {
                        reported_tx.send(delta).unwrap();
                    }
                },
            )
        });
        let subscriber = tracing_subscriber::fmt().with_writer(writer).finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let attempted = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let deadline = started + SOAK;
        let producers = (0..PRODUCERS)
            .map(|producer| {
                let dispatch = dispatch.clone();
                let attempted = attempted.clone();
                std::thread::spawn(move || {
                    tracing::dispatcher::with_default(&dispatch, || {
                        let mut event = 0_u64;
                        while Instant::now() < deadline {
                            tracing::info!(
                                event_name = "logging.soak",
                                producer,
                                event,
                                "sustained log event"
                            );
                            attempted.fetch_add(1, Ordering::Relaxed);
                            event += 1;
                        }
                    });
                })
            })
            .collect::<Vec<_>>();

        for producer in producers {
            producer.join().unwrap();
        }
        drop(dispatch);
        drop(worker_guard);
        stop_monitor.send(()).unwrap();
        monitor.join().unwrap();

        let log_directory = directory.path().join(".soak.jsonl.d");
        let written = std::fs::read_dir(log_directory)
            .unwrap()
            .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
            .map(|bytes| bytes.iter().filter(|byte| **byte == b'\n').count())
            .sum::<usize>();
        let attempted = attempted.load(Ordering::Relaxed);
        let dropped = dropped_lines.dropped_lines();
        let reported = reported_rx.iter().sum::<usize>();
        assert_eq!(attempted, written + dropped);
        assert_eq!(dropped, reported);
        assert!(written > 0);

        eprintln!(
            "logging soak: duration_ms={}, attempted={}, written={}, dropped={}, reported_dropped={}, events_per_second={}",
            started.elapsed().as_millis(),
            attempted,
            written,
            dropped,
            reported,
            (attempted as u128 * 1_000) / started.elapsed().as_millis().max(1)
        );
    }

    #[test]
    fn log_writer_mirrors_events_to_configured_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cipherrun.jsonl");
        let file = rolling_log_file(&path).unwrap();
        let mut writer = LogWriter { file: Some(file) };
        writer.write_all(b"test event\n").unwrap();
        writer.flush().unwrap();

        let log_dir = directory.path().join(".cipherrun.jsonl.d");
        let log_path = std::fs::read_dir(log_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(std::fs::read(log_path).unwrap(), b"test event\n");
    }

    #[test]
    fn daily_rotation_writes_current_utc_bucket_separately_from_previous_day() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cipherrun.jsonl");
        let log_dir = directory.path().join(".cipherrun.jsonl.d");
        std::fs::create_dir(&log_dir).unwrap();
        let now = chrono::Utc::now();
        let current_day = now.format("%Y-%m-%d").to_string();
        let previous_day = (now - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let previous_path = log_dir.join(format!("cipherrun.jsonl.{previous_day}"));
        std::fs::write(&previous_path, b"previous day\n").unwrap();

        let mut file = rolling_log_file(&path).unwrap();
        file.write_all(b"current day\n").unwrap();
        file.flush().unwrap();

        let current_path = log_dir.join(format!("cipherrun.jsonl.{current_day}"));
        assert_eq!(std::fs::read(&current_path).unwrap(), b"current day\n");
        assert_eq!(std::fs::read(&previous_path).unwrap(), b"previous day\n");
    }

    #[test]
    fn rolling_log_retention_is_scoped_to_its_dedicated_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cipherrun.jsonl");
        let log_dir = directory.path().join(".cipherrun.jsonl.d");
        std::fs::create_dir(&log_dir).unwrap();
        for day in 1..=10 {
            std::fs::write(
                log_dir.join(format!("cipherrun.jsonl.2020-01-{day:02}")),
                b"old log\n",
            )
            .unwrap();
        }
        std::fs::write(directory.path().join("cipherrun.jsonl.keep"), b"preserve\n").unwrap();

        let file = rolling_log_file(&path).unwrap();
        drop(file);

        let retained_logs = std::fs::read_dir(&log_dir).unwrap().count();
        assert!(retained_logs <= 7);
        assert_eq!(
            std::fs::read(directory.path().join("cipherrun.jsonl.keep")).unwrap(),
            b"preserve\n"
        );
    }
}
