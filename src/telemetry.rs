//! Optional OpenTelemetry export for the application's tracing spans.

use opentelemetry::{
    Key,
    propagation::{Extractor, TextMapPropagator},
    trace::{TraceContextExt, TracerProvider},
};
use opentelemetry_otlp::{RetryPolicy, SpanExporter, WithHttpConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::{
    Resource,
    resource::{EnvResourceDetector, ResourceDetector},
    trace::SdkTracerProvider,
};
use std::collections::HashMap;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{Layer, filter::filter_fn, registry::LookupSpan};

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
        .with_retry_policy(RetryPolicy {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: 1_600,
            jitter_ms: 100,
        })
        .build()
        .map_err(|_| crate::TlsError::Other("Failed to build OTLP exporter".to_string()))?;
    let provider = SdkTracerProvider::builder()
        .with_resource(telemetry_resource(
            std::env::var("OTEL_SERVICE_NAME").ok(),
            EnvResourceDetector::new()
                .detect()
                .get(&Key::from_static_str("service.name"))
                .map(|value| value.as_str().into_owned()),
        ))
        .with_batch_exporter(exporter)
        .build();
    Ok((
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("cipherrun"))
            .with_filter(filter_fn(|metadata| {
                !(metadata.is_event()
                    && (metadata.target().starts_with("sqlx::query")
                        || (metadata.target() == "cipherrun::database"
                            && *metadata.level() == tracing::Level::DEBUG)))
            })),
        provider,
    ))
}

fn telemetry_resource(
    service_name: Option<String>,
    resource_service_name: Option<String>,
) -> Resource {
    let service_name = service_name
        .filter(|name| !name.is_empty())
        .or_else(|| resource_service_name.filter(|name| !name.is_empty()))
        .unwrap_or_else(|| "cipherrun".to_string());
    Resource::builder().with_service_name(service_name).build()
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
        let resource = telemetry_resource(None, None);
        assert_eq!(
            resource
                .get(&Key::from_static_str("service.name"))
                .map(|value| value.as_str().into_owned()),
            Some("cipherrun".to_string())
        );
        let empty_name = telemetry_resource(Some(String::new()), None);
        assert_eq!(
            empty_name
                .get(&Key::from_static_str("service.name"))
                .map(|value| value.as_str().into_owned()),
            Some("cipherrun".to_string())
        );
    }

    #[test]
    fn configured_service_name_overrides_default_without_mutating_environment() {
        let resource = telemetry_resource(Some("cipherrun-production".to_string()), None);
        assert_eq!(
            resource
                .get(&Key::from_static_str("service.name"))
                .map(|value| value.as_str().into_owned()),
            Some("cipherrun-production".to_string())
        );
    }

    #[test]
    fn service_name_environment_variable_precedes_resource_attributes() {
        let resource = telemetry_resource(
            Some("cipherrun-production".to_string()),
            Some("resource-service".to_string()),
        );
        assert_eq!(
            resource
                .get(&Key::from_static_str("service.name"))
                .map(|value| value.as_str().into_owned()),
            Some("cipherrun-production".to_string())
        );

        let resource = telemetry_resource(None, Some("resource-service".to_string()));
        assert_eq!(
            resource
                .get(&Key::from_static_str("service.name"))
                .map(|value| value.as_str().into_owned()),
            Some("resource-service".to_string())
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
