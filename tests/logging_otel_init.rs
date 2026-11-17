#![cfg(feature = "otel")]

use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use cipherrun::{Args, logging};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

async fn receive_spans(State(sender): State<mpsc::Sender<Vec<u8>>>, body: Bytes) -> StatusCode {
    let _ = sender.send(body.to_vec());
    StatusCode::OK
}

struct EndpointEnvironment {
    endpoint: Option<std::ffi::OsString>,
    trace_endpoint: Option<std::ffi::OsString>,
    batch_size: Option<std::ffi::OsString>,
    rust_log: Option<std::ffi::OsString>,
}

impl EndpointEnvironment {
    fn set(endpoint: &str) -> Self {
        let previous = Self {
            endpoint: std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT"),
            trace_endpoint: std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            batch_size: std::env::var_os("OTEL_BSP_MAX_EXPORT_BATCH_SIZE"),
            rust_log: std::env::var_os("RUST_LOG"),
        };
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint);
            std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
            std::env::set_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "1");
            std::env::set_var("RUST_LOG", "info");
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
            match &self.rust_log {
                Some(value) => std::env::set_var("RUST_LOG", value),
                None => std::env::remove_var("RUST_LOG"),
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

    let start = Arc::new(Barrier::new(9));
    let initializers = (0..8)
        .map(|_| {
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                logging::initialize(&Args::default())
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    let guards = initializers
        .into_iter()
        .map(|initializer| {
            initializer
                .join()
                .expect("logger initialization thread should not panic")
                .expect("concurrent logger initialization should reuse the installed subscriber")
        })
        .collect::<Vec<_>>();
    let span = tracing::info_span!("logging.otlp.integration");
    span.in_scope(|| {
        tracing::info!(event_name = "logging.otlp.test", "export test span");
        tracing::debug!(event_name = "logging.otlp.debug", "filtered debug event");
    });
    drop(span);
    tokio::task::spawn_blocking(move || drop(guards))
        .await
        .unwrap();

    let payload =
        tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(5)).unwrap())
            .await
            .unwrap();
    let payload = String::from_utf8_lossy(&payload);
    assert!(payload.contains("logging.otlp.test"), "{payload}");
    assert!(!payload.contains("logging.otlp.debug"), "{payload}");
    collector.abort();
}
