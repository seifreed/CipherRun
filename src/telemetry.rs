//! Optional OpenTelemetry export for the application's tracing spans.

use opentelemetry::{
    global,
    propagation::{Extractor, TextMapPropagator},
    trace::{TraceContextExt, TracerProvider},
};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::collections::HashMap;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::registry::LookupSpan;

pub fn current_traceparent() -> Option<String> {
    let context = tracing::Span::current().context();
    traceparent_for_context(&context)
}

fn traceparent_for_context(context: &opentelemetry::Context) -> Option<String> {
    if !context.span().span_context().is_valid() {
        return None;
    }
    let mut carrier = HashMap::new();
    TraceContextPropagator::new().inject_context(context, &mut carrier);
    carrier.remove("traceparent")
}

pub fn context_from_traceparent(value: &str) -> Option<opentelemetry::Context> {
    let context = TraceContextPropagator::new().extract(&TraceParentExtractor(value));
    context.span().span_context().is_valid().then_some(context)
}

struct TraceParentExtractor<'a>(&'a str);

impl Extractor for TraceParentExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        (key == "traceparent").then_some(self.0)
    }

    fn keys(&self) -> Vec<&str> {
        vec!["traceparent"]
    }
}

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

#[cfg(test)]
mod tests {
    use super::{context_from_traceparent, traceparent_for_context};
    use opentelemetry::trace::{TraceContextExt, Tracer, TracerProvider};
    use opentelemetry_sdk::trace::SdkTracerProvider;

    #[test]
    fn traceparent_round_trips_across_background_job_boundary() {
        let provider = SdkTracerProvider::builder().build();
        let span = provider.tracer("test").start("request");
        let context = opentelemetry::Context::new().with_span(span);

        let traceparent = traceparent_for_context(&context).expect("valid request context");
        let extracted = context_from_traceparent(&traceparent).expect("valid traceparent");

        assert_eq!(
            extracted.span().span_context().trace_id(),
            context.span().span_context().trace_id()
        );
        assert_eq!(
            extracted.span().span_context().span_id(),
            context.span().span_context().span_id()
        );
        assert!(context_from_traceparent("invalid").is_none());
    }
}
