#![cfg(feature = "otel")]

use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use cipherrun::{Args, logging};
use std::sync::mpsc;
use std::time::Duration;

async fn receive_spans(State(sender): State<mpsc::Sender<usize>>, body: Bytes) -> StatusCode {
    let _ = sender.send(body.len());
    StatusCode::OK
}

struct EndpointEnvironment {
    endpoint: Option<std::ffi::OsString>,
    trace_endpoint: Option<std::ffi::OsString>,
    batch_size: Option<std::ffi::OsString>,
}

impl EndpointEnvironment {
    fn set(endpoint: &str) -> Self {
        let previous = Self {
            endpoint: std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT"),
            trace_endpoint: std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            batch_size: std::env::var_os("OTEL_BSP_MAX_EXPORT_BATCH_SIZE"),
        };
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint);
            std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
            std::env::set_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "1");
        }
        previous
    }
}

impl Drop for EndpointEnvironment {
    fn drop(&mut self) {
        unsafe {
            match &self.endpoint {
                Some(value) => std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", value),
                None => std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT"),
            }
            match &self.trace_endpoint {
                Some(value) => std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", value),
                None => std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            }
            match &self.batch_size {
                Some(value) => std::env::set_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", value),
                None => std::env::remove_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE"),
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn logging_initializer_exports_to_a_local_collector() {
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

    let guard = logging::initialize(&Args::default()).unwrap();
    let span = tracing::info_span!("logging.otlp.integration");
    span.in_scope(|| tracing::info!(event_name = "logging.otlp.test", "export test span"));
    drop(span);
    tokio::task::spawn_blocking(move || drop(guard))
        .await
        .unwrap();

    let payload_size =
        tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(5)).unwrap())
            .await
            .unwrap();
    assert!(payload_size > 0);
    collector.abort();
}
