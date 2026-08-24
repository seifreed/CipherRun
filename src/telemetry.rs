//! Optional OpenTelemetry export for the application's tracing spans.

use opentelemetry::global;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::registry::LookupSpan;

pub fn layer<S>() -> Result<impl tracing_subscriber::Layer<S>, crate::TlsError>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    let exporter = SpanExporter::builder()
        .with_http()
        .build()
        .map_err(|error| {
            crate::TlsError::Other(format!("Failed to build OTLP exporter: {error}"))
        })?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    global::set_tracer_provider(provider);

    Ok(tracing_opentelemetry::layer().with_tracer(global::tracer("cipherrun")))
}
