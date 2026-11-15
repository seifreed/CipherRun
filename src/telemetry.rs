//! Optional OpenTelemetry export for the application's tracing spans.

use opentelemetry::{
    global,
    propagation::{Extractor, TextMapPropagator},
    trace::{TraceContextExt, TracerProvider},
};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
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
        .with_resource(telemetry_resource())
        .with_batch_exporter(exporter)
        .build();
    global::set_tracer_provider(provider.clone());

    Ok((
        tracing_opentelemetry::layer().with_tracer(provider.tracer("cipherrun")),
        provider,
    ))
}

fn telemetry_resource() -> Resource {
    Resource::builder().with_service_name("cipherrun").build()
}

#[cfg(test)]
mod tests {
    use super::{
        context_from_traceparent, current_traceparent, telemetry_resource, traceparent_for_context,
    };
    use opentelemetry::Key;
    use opentelemetry::trace::{TraceContextExt, Tracer, TracerProvider};
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::prelude::*;

    #[test]
    fn resource_identifies_the_service() {
        let resource = telemetry_resource();
        assert!(
            resource
                .get(&Key::from_static_str("service.name"))
                .is_some()
        );
    }

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

    #[test]
    fn active_request_span_context_continues_into_job_span() {
        let provider = SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));

        tracing::subscriber::with_default(subscriber, || {
            let request_span = tracing::info_span!("http.request");
            request_span.in_scope(|| {
                let traceparent = current_traceparent().expect("active request trace");
                let parent = context_from_traceparent(&traceparent).expect("valid parent");
                let job_span = tracing::info_span!("scan.job");
                job_span.set_parent(parent).unwrap();

                assert_eq!(
                    request_span.context().span().span_context().trace_id(),
                    job_span.context().span().span_context().trace_id()
                );
            });
        });

        provider.shutdown().unwrap();
    }
}
