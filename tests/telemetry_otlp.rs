#![cfg(feature = "otel")]

use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

static OTLP_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type RetryState = (Arc<AtomicUsize>, mpsc::Sender<(usize, StatusCode)>);

#[derive(Clone)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

struct LogBufferWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogBufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogBufferWriter(self.0.clone())
    }
}

impl std::io::Write for LogBufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn receive_spans(State(sender): State<mpsc::Sender<usize>>, body: Bytes) -> StatusCode {
    let _ = sender.send(body.len());
    StatusCode::OK
}

async fn reject_spans(
    State(sender): State<mpsc::Sender<(usize, StatusCode)>>,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let _ = sender.send((body.len(), StatusCode::SERVICE_UNAVAILABLE));
    (StatusCode::SERVICE_UNAVAILABLE, "token=collector-secret")
}

async fn recover_spans(
    State((attempt, sender)): State<RetryState>,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let status = if attempt.fetch_add(1, Ordering::SeqCst) == 0 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    let _ = sender.send((body.len(), status));
    (status, "token=collector-secret")
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
    let _environment_lock = OTLP_ENV_LOCK.lock().await;
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

#[tokio::test(flavor = "current_thread")]
async fn otlp_collector_failure_is_reported_without_panicking() {
    let _environment_lock = OTLP_ENV_LOCK.lock().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let _environment = EndpointEnvironment::set(&endpoint);
    let (sender, receiver) = mpsc::channel();
    let collector = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/traces", post(reject_spans))
                .with_state(sender),
        )
        .await
        .unwrap();
    });

    let (otel_layer, provider) = cipherrun::telemetry::layer().unwrap();
    let output = LogBuffer(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(output.clone())
                .with_filter(EnvFilter::new("trace")),
        )
        .with(otel_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
    tracing::info_span!("otlp.failure.integration")
        .in_scope(|| tracing::info!(event_name = "otlp.failure.test", "export failure test"));
    let shutdown = tokio::task::spawn_blocking(move || provider.shutdown())
        .await
        .unwrap();

    assert!(shutdown.is_ok());
    let attempts = (0..4)
        .map(|_| receiver.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect::<Vec<_>>();
    assert!(attempts.iter().all(|(payload_size, _)| *payload_size > 0));
    assert!(
        attempts
            .iter()
            .all(|(_, status)| *status == StatusCode::SERVICE_UNAVAILABLE)
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("BatchSpanProcessor.ExportError"), "{logs}");
    assert!(logs.contains("HTTP export failed"), "{logs}");
    assert!(!logs.contains("collector-secret"), "{logs}");
    collector.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn otlp_http_retries_transient_failure_until_export_succeeds() {
    let _environment_lock = OTLP_ENV_LOCK.lock().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let _environment = EndpointEnvironment::set(&endpoint);
    let (sender, receiver) = mpsc::channel();
    let attempt = Arc::new(AtomicUsize::new(0));
    let collector_attempt = attempt.clone();
    let collector = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/traces", post(recover_spans))
                .with_state((collector_attempt, sender)),
        )
        .await
        .unwrap();
    });

    let (otel_layer, provider) = cipherrun::telemetry::layer().unwrap();
    let subscriber = tracing_subscriber::registry().with(otel_layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info_span!("otlp.retry.integration")
            .in_scope(|| tracing::info!(event_name = "otlp.retry.test", "retry test span"));
    });
    tokio::task::spawn_blocking(move || provider.shutdown().unwrap())
        .await
        .unwrap();

    let attempts = (0..2)
        .map(|_| receiver.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(attempts[0].1, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(attempts[1].1, StatusCode::OK);
    assert!(attempts.iter().all(|(payload_size, _)| *payload_size > 0));
    assert_eq!(attempt.load(Ordering::SeqCst), 2);
    collector.abort();
}
