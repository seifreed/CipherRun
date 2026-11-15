#![cfg(feature = "otel")]

use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use std::sync::mpsc;
use std::time::Duration;
use tracing_subscriber::prelude::*;

async fn receive_spans(State(sender): State<mpsc::Sender<usize>>, body: Bytes) -> StatusCode {
    let _ = sender.send(body.len());
    StatusCode::OK
}

struct EndpointEnvironment {
    previous_endpoint: Option<std::ffi::OsString>,
    previous_trace_endpoint: Option<std::ffi::OsString>,
}

impl EndpointEnvironment {
    fn set(endpoint: &str) -> Self {
        let previous_endpoint = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT");
        let previous_trace_endpoint = std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint);
            std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
        }
        Self {
            previous_endpoint,
            previous_trace_endpoint,
        }
    }
}

impl Drop for EndpointEnvironment {
    fn drop(&mut self) {
        unsafe {
            match &self.previous_endpoint {
                Some(value) => std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", value),
                None => std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT"),
            }
            match &self.previous_trace_endpoint {
                Some(value) => std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", value),
                None => std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn otlp_http_export_reaches_a_local_collector() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let _environment = EndpointEnvironment::set(&endpoint);
    let (sender, receiver) = mpsc::channel();
    let collector = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/traces", post(receive_spans))
                .with_state(sender),
        )
        .await
        .unwrap();
    });

    let (otel_layer, provider) = cipherrun::telemetry::layer().unwrap();
    let subscriber = tracing_subscriber::registry().with(otel_layer);
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("otlp.integration");
        span.in_scope(|| tracing::info!(event_name = "otlp.test", "export test span"));
    });
    tokio::task::spawn_blocking(move || provider.shutdown().unwrap())
        .await
        .unwrap();

    let payload_size =
        tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(5)).unwrap())
            .await
            .unwrap();
    assert!(payload_size > 0);
    collector.abort();
}
