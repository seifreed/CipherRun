//! Optional OpenTelemetry export for the application's tracing spans.

use opentelemetry::{global, trace::TracerProvider};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::registry::LookupSpan;

pub fn layer<S>() -> Result<(impl tracing_subscriber::Layer<S>, SdkTracerProvider), crate::TlsError>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    let exporter = SpanExporter::builder()
        .with_http()
        .build()
        .map_err(|_| crate::TlsError::Other("Failed to build OTLP exporter".to_string()))?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    global::set_tracer_provider(provider.clone());

    Ok((
        tracing_opentelemetry::layer().with_tracer(provider.tracer("cipherrun")),
        provider,
    ))
}
