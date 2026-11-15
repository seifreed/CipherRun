use crate::{Args, Result, TlsError};
use std::io::{self, Write};
use tracing_subscriber::EnvFilter;
#[cfg(not(feature = "otel"))]
use tracing_subscriber::FmtSubscriber;

pub fn initialize(args: &Args) -> Result<LoggingGuard> {
    let filter = resolve_log_filter(
        std::env::var("RUST_LOG").ok().as_deref(),
        args.output.verbose,
    );
    let file = args
        .output
        .logfile
        .as_ref()
        .map(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        })
        .transpose()?;
    let (writer, writer_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .finish(LogWriter { file });
    let json = json_logs_enabled(std::env::var("CIPHERRUN_LOG_FORMAT").ok().as_deref());

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

    Ok(LoggingGuard {
        _writer_guard: writer_guard,
        #[cfg(feature = "otel")]
        tracer_provider,
    })
}

pub struct LoggingGuard {
    _writer_guard: tracing_appender::non_blocking::WorkerGuard,
    #[cfg(feature = "otel")]
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

#[cfg(feature = "otel")]
impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if let Some(provider) = &self.tracer_provider
            && provider.shutdown().is_err()
        {
            tracing::warn!(
                event_name = "telemetry.flush.failed",
                "Failed to flush OpenTelemetry spans during shutdown"
            );
        }
    }
}

struct LogWriter {
    file: Option<std::fs::File>,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stderr().write_all(buf)?;
        if let Some(file) = &mut self.file {
            file.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()?;
        if let Some(file) = &mut self.file {
            file.flush()?;
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::{LogWriter, json_logs_enabled, resolve_log_filter};
    use std::io::Write;

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
    fn log_writer_mirrors_events_to_configured_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_owned();
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(path.clone())
            .unwrap();
        let mut writer = LogWriter { file: Some(file) };
        writer.write_all(b"test event\n").unwrap();
        writer.flush().unwrap();

        assert_eq!(std::fs::read(path).unwrap(), b"test event\n");
    }
}
