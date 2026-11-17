use crate::{Args, Result, TlsError};
use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Mutex, Once};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{Event, Subscriber};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
#[cfg(not(feature = "otel"))]
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::fmt::{
    FmtContext,
    format::{FormatEvent, FormatFields, Writer},
};
use tracing_subscriber::registry::LookupSpan;

static SAFE_PANIC_HOOK: Once = Once::new();
static LOGGING_INITIALIZATION: Mutex<()> = Mutex::new(());

/// Replace Rust's default panic hook, which prints the caller-controlled payload.
pub fn install_safe_panic_hook() {
    SAFE_PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let source_line = info.location().map_or(0, std::panic::Location::line);
            if tracing::dispatcher::has_been_set() {
                tracing::error!(
                    event_name = "process.panic",
                    error_type = "panic",
                    error_code = "panic_unwind",
                    source_line,
                    outcome = "panicked",
                    "Process panicked; panic payload omitted"
                );
            } else {
                eprintln!(
                    "ERROR process.panic error_type=panic error_code=panic_unwind source_line={source_line} outcome=panicked message=\"Panic payload omitted\""
                );
            }
        }));
    });
}

pub fn initialize(args: &Args) -> Result<LoggingGuard> {
    let _initialization = LOGGING_INITIALIZATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let json = json_logs_enabled(std::env::var("CIPHERRUN_LOG_FORMAT").ok().as_deref());
    if tracing::dispatcher::has_been_set() {
        tracing::info!(
            event_name = "logging.subscriber.reused",
            requested_file_destination = args.output.logfile.is_some(),
            outcome = "existing_subscriber",
            "Using the already initialized tracing subscriber"
        );
        return Ok(LoggingGuard {
            writer_guard: None,
            dropped_log_lines: None,
            json,
            drop_monitor: None,
            #[cfg(feature = "otel")]
            tracer_provider: None,
        });
    }

    let filter = resolve_log_filter(
        std::env::var("RUST_LOG").ok().as_deref(),
        args.output.verbose,
    );
    let file = args.output.logfile.as_ref().and_then(|path| {
        rolling_log_file(path).map_or_else(
            |_| {
                report_log_file_fallback(json);
                None
            },
            Some,
        )
    });
    let file_destination_enabled = file.is_some();
    let (writer, writer_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .finish(LogWriter {
            file,
            file_failure_reported: false,
        });
    let dropped_log_lines = writer.error_counter();

    #[cfg(feature = "otel")]
    let tracer_provider = {
        use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

        match crate::telemetry::layer() {
            Ok((otel_layer, provider)) => {
                let fmt_layer = if json {
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(writer)
                        .with_filter(filter)
                        .boxed()
                } else {
                    tracing_subscriber::fmt::layer()
                        .event_format(SafeTextFormat::default())
                        .with_writer(writer)
                        .with_filter(filter)
                        .boxed()
                };
                tracing_subscriber::registry()
                    .with(fmt_layer)
                    .with(otel_layer)
                    .try_init()
                    .map_err(|_| TlsError::Other("Failed to set tracing subscriber".to_string()))?;
                opentelemetry::global::set_tracer_provider(provider.clone());
                Some(provider)
            }
            Err(error) => {
                let result = if json {
                    tracing_subscriber::fmt()
                        .json()
                        .with_env_filter(filter)
                        .with_writer(writer)
                        .try_init()
                } else {
                    tracing_subscriber::fmt()
                        .event_format(SafeTextFormat::default())
                        .with_env_filter(filter)
                        .with_writer(writer)
                        .try_init()
                };
                result
                    .map_err(|_| TlsError::Other("Failed to set tracing subscriber".to_string()))?;
                tracing::warn!(
                    event_name = "telemetry.exporter.initialization_failed",
                    error_type = "otlp_exporter",
                    error_code = error.observability_code(),
                    outcome = "local_logging_only",
                    "OpenTelemetry setup failed; continuing with local logging"
                );
                None
            }
        }
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
                .event_format(SafeTextFormat::default())
                .with_env_filter(filter)
                .with_writer(writer)
                .try_init()
        };
        result.map_err(|_| TlsError::Other("Failed to set tracing subscriber".to_string()))?;
    }

    let drop_monitor = start_drop_monitor(dropped_log_lines.clone(), json);
    tracing::info!(
        event_name = "logging.subscriber.initialized",
        operation = "initialize",
        outcome = "started",
        format = if json { "json" } else { "text" },
        file_destination_enabled,
        drop_monitor_enabled = drop_monitor.is_some(),
        "Tracing subscriber initialized"
    );
    Ok(LoggingGuard {
        writer_guard: Some(writer_guard),
        dropped_log_lines: Some(dropped_log_lines),
        json,
        drop_monitor,
        #[cfg(feature = "otel")]
        tracer_provider,
    })
}

#[derive(Default)]
struct SafeTextFormat(tracing_subscriber::fmt::format::Format);

impl<S, N> FormatEvent<S, N> for SafeTextFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, N>,
        writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut writer = SanitizingWriter {
            output: writer,
            pending_newline: false,
        };
        self.0
            .format_event(context, Writer::new(&mut writer), event)?;
        writer.finish()
    }
}

struct SanitizingWriter<'a> {
    output: Writer<'a>,
    pending_newline: bool,
}

impl SanitizingWriter<'_> {
    fn finish(&mut self) -> fmt::Result {
        if self.pending_newline {
            self.output.write_str("\n")?;
            self.pending_newline = false;
        }
        Ok(())
    }
}

impl fmt::Write for SanitizingWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.pending_newline && !value.is_empty() {
            self.output.write_str("\\n")?;
            self.pending_newline = false;
        }

        let mut start = 0;
        for (index, character) in value.char_indices() {
            if character.is_control() {
                self.output.write_str(&value[start..index])?;
                if character == '\n' && index + 1 == value.len() {
                    self.pending_newline = true;
                } else {
                    write!(self.output, "{}", character.escape_default())?;
                }
                start = index + character.len_utf8();
            }
        }
        self.output.write_str(&value[start..])
    }
}

pub struct LoggingGuard {
    writer_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    dropped_log_lines: Option<tracing_appender::non_blocking::ErrorCounter>,
    json: bool,
    drop_monitor: Option<(SyncSender<()>, JoinHandle<usize>)>,
    #[cfg(feature = "otel")]
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if self.writer_guard.is_some() {
            tracing::info!(
                event_name = "logging.subscriber.shutdown",
                operation = "flush",
                outcome = "flush_requested",
                "Flushing tracing subscriber during shutdown"
            );
        }

        #[cfg(feature = "otel")]
        if let Some(provider) = &self.tracer_provider
            && provider.shutdown().is_err()
        {
            tracing::warn!(
                event_name = "telemetry.flush.failed",
                "Failed to flush OpenTelemetry spans during shutdown"
            );
        }

        let already_reported = if let Some((stop, monitor)) = self.drop_monitor.take() {
            let _ = stop.send(());
            join_drop_monitor(monitor)
        } else {
            0
        };
        drop(self.writer_guard.take());
        let dropped_lines = self
            .dropped_log_lines
            .as_ref()
            .map_or(0, |counter| counter.dropped_lines());
        report_dropped_log_lines(dropped_lines.saturating_sub(already_reported), self.json);
    }
}

struct LogWriter {
    file: Option<RollingFileAppender>,
    file_failure_reported: bool,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stderr = io::stderr().lock();
        let Self {
            file,
            file_failure_reported,
        } = self;
        let file = file.as_mut().map(|file| file as &mut dyn Write);
        write_to_destinations(buf, &mut stderr, file, || {
            if !*file_failure_reported {
                report_log_file_write_fallback();
                *file_failure_reported = true;
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        let Self {
            file,
            file_failure_reported,
        } = self;
        let stderr_result = stderr.flush();
        let file_result = file.as_mut().map(Write::flush);
        destination_result(stderr_result, file_result, || {
            if !*file_failure_reported {
                report_log_file_write_fallback();
                *file_failure_reported = true;
            }
        })
    }
}

fn write_to_destinations(
    buf: &[u8],
    stderr: &mut dyn Write,
    file: Option<&mut dyn Write>,
    report_file_failure: impl FnOnce(),
) -> io::Result<usize> {
    let stderr_result = stderr.write_all(buf);
    let file_result = file.map(|file| file.write_all(buf));
    destination_result(stderr_result, file_result, report_file_failure).map(|()| buf.len())
}

fn destination_result(
    stderr_result: io::Result<()>,
    file_result: Option<io::Result<()>>,
    report_file_failure: impl FnOnce(),
) -> io::Result<()> {
    if file_result.as_ref().is_some_and(|result| result.is_err()) {
        report_file_failure();
    }
    match (stderr_result, file_result) {
        (Ok(()), _) | (Err(_), Some(Ok(()))) => Ok(()),
        (Err(stderr_error), _) => Err(stderr_error),
    }
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
        .add_directive(
            "hyper_util::client::legacy=off"
                .parse()
                .expect("static privacy filter directive should parse"),
        )
        .add_directive(
            "hyper_util::client::legacy::pool=off"
                .parse()
                .expect("static privacy filter directive should parse"),
        )
        .add_directive(
            "hyper_util::client::legacy::connect::http=off"
                .parse()
                .expect("static privacy filter directive should parse"),
        )
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
        });
    let monitor = match monitor {
        Ok(monitor) => monitor,
        Err(_) => {
            report_drop_monitor_start_failure();
            return None;
        }
    };
    Some((stop, monitor))
}

fn report_drop_monitor_start_failure() {
    tracing::warn!(
        event_name = "logging.drop_monitor.start_failed",
        operation = "start_drop_monitor",
        error_type = "thread_spawn",
        error_code = "thread_spawn_failed",
        outcome = "shutdown_counter_only",
        "Could not start the log drop monitor"
    );
}

fn join_drop_monitor(monitor: JoinHandle<usize>) -> usize {
    match monitor.join() {
        Ok(reported) => reported,
        Err(_) => {
            tracing::warn!(
                event_name = "logging.drop_monitor.join_failed",
                operation = "shutdown",
                error_type = "panic",
                error_code = "drop_monitor_panicked",
                outcome = "final_count_may_repeat",
                "Log drop monitor failed before shutdown"
            );
            0
        }
    }
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

fn report_log_file_write_fallback() {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let line = format_log_file_write_fallback_event(&timestamp);
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

fn format_log_file_write_fallback_event(timestamp: &str) -> String {
    serde_json::json!({
        "timestamp": timestamp,
        "level": "WARN",
        "fields": {
            "event_name": "logging.file_destination.write_failed",
            "operation": "write_log_file",
            "error_type": "file_destination",
            "error_code": "filesystem_error",
            "outcome": "stderr_only",
            "message": "Log file write failed; continuing with stderr"
        },
        "target": "cipherrun::logging"
    })
    .to_string()
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
        LogWriter, SafeTextFormat, format_dropped_log_event, format_log_file_fallback_event,
        format_log_file_write_fallback_event, install_safe_panic_hook, join_drop_monitor,
        json_logs_enabled, monitor_dropped_log_lines, report_drop_monitor_start_failure,
        resolve_log_filter, rolling_log_file, write_to_destinations,
    };
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex, mpsc};
    use std::time::{Duration, Instant};
    use tracing_subscriber::fmt::MakeWriter;

    #[test]
    fn safe_panic_hook_child() {
        let Ok(mode) = std::env::var("CIPHERRUN_SAFE_PANIC_HOOK_CHILD") else {
            return;
        };

        if mode == "json" {
            tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::ERROR)
                .try_init()
                .unwrap();
        }
        install_safe_panic_hook();
        panic!("private-panic-payload");
    }

    #[test]
    fn safe_panic_hook_redacts_payload_with_and_without_subscriber() {
        let run_child = |mode| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "logging::tests::safe_panic_hook_child",
                    "--nocapture",
                ])
                .env("CIPHERRUN_SAFE_PANIC_HOOK_CHILD", mode)
                .output()
                .unwrap()
        };
        let structured = run_child("json");
        assert!(!structured.status.success());
        let structured_output = format!(
            "{}{}",
            String::from_utf8(structured.stdout).unwrap(),
            String::from_utf8(structured.stderr).unwrap()
        );
        let event = structured_output
            .lines()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .unwrap_or_else(|| panic!("panic hook should emit a JSON event: {structured_output}"));
        assert_eq!(event["fields"]["event_name"], "process.panic");
        assert_eq!(event["fields"]["error_type"], "panic");
        assert_eq!(event["fields"]["error_code"], "panic_unwind");
        assert_eq!(event["fields"]["outcome"], "panicked");
        assert!(event["fields"]["source_line"].is_number());
        assert!(!structured_output.contains("private-panic-payload"));

        let fallback = run_child("stderr");
        assert!(!fallback.status.success());
        let fallback_output = format!(
            "{}{}",
            String::from_utf8(fallback.stdout).unwrap(),
            String::from_utf8(fallback.stderr).unwrap()
        );
        assert!(
            fallback_output.contains("ERROR process.panic"),
            "{fallback_output}"
        );
        assert!(
            fallback_output.contains("error_code=panic_unwind"),
            "{fallback_output}"
        );
        assert!(!fallback_output.contains("private-panic-payload"));
    }

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

        let mut reported = false;
        write_to_destinations(b"event\n", &mut FailingWriter, Some(&mut file), || {
            reported = true;
        })
        .expect("the file destination successfully stored the event");

        assert!(!reported);
        assert_eq!(*file_output.0.lock().unwrap(), b"event\n");
    }

    #[test]
    fn file_failure_does_not_skip_stderr_destination() {
        let stderr_output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let mut stderr = BufferWriter(stderr_output.0.clone());

        let mut reported = false;
        write_to_destinations(b"event\n", &mut stderr, Some(&mut FailingWriter), || {
            reported = true;
        })
        .expect("stderr successfully stored the event");

        assert!(reported, "file destination failure should be surfaced");
        assert_eq!(*stderr_output.0.lock().unwrap(), b"event\n");
    }

    #[test]
    fn both_destination_failures_return_an_io_error() {
        let mut reported = false;
        let error = write_to_destinations(
            b"event\n",
            &mut FailingWriter,
            Some(&mut FailingWriter),
            || reported = true,
        )
        .expect_err("an event with no successful destination should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(reported);
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
    fn filter_suppresses_host_bearing_hyper_diagnostics_even_at_trace() {
        let output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_env_filter(resolve_log_filter(
                Some(
                    "trace,hyper_util::client::legacy=trace,hyper_util::client::legacy::pool=trace,hyper_util::client::legacy::connect::http=trace",
                ),
                0,
            ))
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(
                target: "hyper_util::client::legacy::pool",
                message = "checkout waiting for idle connection: (https, private.example:443)"
            );
            tracing::debug!(
                target: "cipherrun::protocols::alpn",
                event_name = "http3.request.inconclusive",
                outcome = "inconclusive",
                "HTTP/3 probe failed"
            );
        });

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("private.example"));
        assert!(output.contains("http3.request.inconclusive"));
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
            tracing::info!(input = %untrusted, "test event {untrusted}");
        });

        let bytes = output.0.lock().unwrap().clone();
        let serialized = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(serialized.lines().count(), 1);
        let event: serde_json::Value = serde_json::from_str(serialized).unwrap();
        assert_eq!(event["fields"]["input"], untrusted);
    }

    #[test]
    fn text_format_does_not_allow_untrusted_fields_to_inject_lines() {
        let output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .event_format(SafeTextFormat::default())
            .with_writer(output.clone())
            .finish();
        let untrusted = "value\nlevel=ERROR\r\u{001b}[2J";

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(input = %untrusted, "test event {untrusted}");
        });

        let bytes = output.0.lock().unwrap().clone();
        let serialized = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(serialized.lines().count(), 1, "{serialized:?}");
        let content = serialized.trim_end_matches('\n');
        assert!(!content.contains('\r'), "{serialized:?}");
        assert!(!content.contains('\u{001b}'), "{serialized:?}");
        assert!(content.contains("\\n"), "{serialized:?}");
        assert!(content.contains("\\r"), "{serialized:?}");
        assert!(content.contains("\\u{1b}"), "{serialized:?}");
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
    fn failed_file_write_uses_a_safe_json_fallback_event() {
        let serialized = format_log_file_write_fallback_event("2026-11-15T12:00:00.000000Z");
        let event: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event["level"], "WARN");
        assert_eq!(
            event["fields"]["event_name"],
            "logging.file_destination.write_failed"
        );
        assert_eq!(event["fields"]["error_code"], "filesystem_error");
        assert_eq!(event["fields"]["outcome"], "stderr_only");
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
    fn drop_monitor_panic_is_logged_during_shutdown() {
        let output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(output.clone())
            .finish();
        let monitor = std::thread::spawn(|| panic!("simulated monitor panic"));

        let reported = tracing::subscriber::with_default(subscriber, || join_drop_monitor(monitor));

        assert_eq!(reported, 0);
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("logging.drop_monitor.join_failed"),
            "{output}"
        );
        assert!(output.contains("drop_monitor_panicked"), "{output}");
        assert!(output.contains("final_count_may_repeat"), "{output}");
    }

    #[test]
    fn drop_monitor_start_failure_is_logged_without_platform_details() {
        let output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, report_drop_monitor_start_failure);

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["level"], "WARN");
        assert_eq!(
            event["fields"]["event_name"],
            "logging.drop_monitor.start_failed"
        );
        assert_eq!(event["fields"]["operation"], "start_drop_monitor");
        assert_eq!(event["fields"]["error_type"], "thread_spawn");
        assert_eq!(event["fields"]["error_code"], "thread_spawn_failed");
        assert_eq!(event["fields"]["outcome"], "shutdown_counter_only");
        assert!(!output.contains("os error"));
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
        let subscriber = tracing_subscriber::fmt()
            .event_format(SafeTextFormat::default())
            .with_writer(writer)
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let untrusted = "value\nlevel=ERROR\r\u{001b}[2J";
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
                                input = %untrusted,
                                "concurrent load event {untrusted}"
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
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert_eq!(output.lines().count(), PRODUCERS * EVENTS_PER_PRODUCER);
        assert!(!output.contains('\r'));
        assert!(!output.contains('\u{001b}'));
        assert!(output.contains("\\n"));
        assert!(output.contains("\\r"));
        assert!(output.contains("\\u{1b}"));
    }

    #[test]
    #[ignore = "manual 30-second paced synthetic logging load validation"]
    fn rolling_file_writer_handles_paced_synthetic_rate_without_loss() {
        const PRODUCERS: usize = 8;
        const EVENTS_PER_PRODUCER: usize = 3_750;
        const INTERVAL: Duration = Duration::from_millis(8);

        let directory = tempfile::tempdir().unwrap();
        let logfile = directory.path().join("paced.jsonl");
        let file = rolling_log_file(&logfile).unwrap();
        let (writer, worker_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(true)
            .finish(file);
        let dropped_lines = writer.error_counter();
        let subscriber = tracing_subscriber::fmt()
            .event_format(SafeTextFormat::default())
            .with_writer(writer)
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let start_gate = Arc::new(Barrier::new(PRODUCERS));
        let started = Instant::now();
        let producers = (0..PRODUCERS)
            .map(|producer| {
                let dispatch = dispatch.clone();
                let start_gate = start_gate.clone();
                std::thread::spawn(move || {
                    tracing::dispatcher::with_default(&dispatch, || {
                        start_gate.wait();
                        let began = Instant::now();
                        let mut latencies = Vec::with_capacity(EVENTS_PER_PRODUCER);
                        for event in 0..EVENTS_PER_PRODUCER {
                            let scheduled = began + INTERVAL * event as u32;
                            if let Some(delay) = scheduled.checked_duration_since(Instant::now()) {
                                std::thread::sleep(delay);
                            }
                            let emitted = Instant::now();
                            tracing::info!(
                                event_name = "logging.load.paced",
                                producer,
                                event,
                                "paced load event"
                            );
                            latencies.push(emitted.elapsed().as_nanos());
                        }
                        latencies
                    })
                })
            })
            .collect::<Vec<_>>();

        let mut latencies = producers
            .into_iter()
            .flat_map(|producer| producer.join().unwrap())
            .collect::<Vec<_>>();
        drop(dispatch);
        drop(worker_guard);

        let attempted = PRODUCERS * EVENTS_PER_PRODUCER;
        let dropped = dropped_lines.dropped_lines();
        let log_directory = directory.path().join(".paced.jsonl.d");
        let written = std::fs::read_dir(log_directory)
            .unwrap()
            .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
            .map(|bytes| bytes.iter().filter(|byte| **byte == b'\n').count())
            .sum::<usize>();
        let elapsed_ms = started.elapsed().as_millis().max(1);
        latencies.sort_unstable();
        let p50_us = latencies[latencies.len() / 2] / 1_000;
        let p99_us = latencies[latencies.len() * 99 / 100] / 1_000;

        assert_eq!(dropped, 0);
        assert_eq!(written, attempted);
        eprintln!(
            "paced logging load: attempted={attempted}, written={written}, dropped={dropped}, events_per_second={}, emit_p50_us={p50_us}, emit_p99_us={p99_us}",
            attempted as u128 * 1_000 / elapsed_ms
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
        let attempted = attempted.load(Ordering::Relaxed);
        let dropped = dropped_lines.dropped_lines();
        let reported = reported_rx.iter().sum::<usize>();
        let drain_deadline = Instant::now() + Duration::from_secs(30);
        let written = loop {
            let written = std::fs::read_dir(&log_directory)
                .unwrap()
                .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
                .map(|bytes| bytes.iter().filter(|byte| **byte == b'\n').count())
                .sum::<usize>();
            if written + dropped >= attempted || Instant::now() >= drain_deadline {
                break written;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
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
        let mut writer = LogWriter {
            file: Some(file),
            file_failure_reported: false,
        };
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
