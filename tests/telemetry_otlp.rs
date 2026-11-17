#![cfg(feature = "otel")]

use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use opentelemetry::trace::Tracer;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

static OTLP_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type RetryState = (Arc<AtomicUsize>, mpsc::Sender<(usize, StatusCode)>);
type OutageSoakState = (
    Arc<tokio::sync::Semaphore>,
    tokio::sync::mpsc::Sender<usize>,
    tokio::sync::mpsc::Sender<(usize, StatusCode)>,
);

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

async fn receive_span_body(State(sender): State<mpsc::Sender<Vec<u8>>>, body: Bytes) -> StatusCode {
    let _ = sender.send(body.to_vec());
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
    let status = if attempt.fetch_add(1, Ordering::SeqCst) < 5 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    let _ = sender.send((body.len(), status));
    (status, "token=collector-secret")
}

async fn hold_spans_until_recovered(
    State((recovery, started, completed)): State<OutageSoakState>,
    body: Bytes,
) -> StatusCode {
    let _ = started.try_send(body.len());
    let Ok(permit) = recovery.acquire().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    permit.forget();
    let _ = completed.send((body.len(), StatusCode::OK)).await;
    StatusCode::OK
}

struct EndpointEnvironment {
    previous_endpoint: Option<std::ffi::OsString>,
    previous_trace_endpoint: Option<std::ffi::OsString>,
    previous_batch_size: Option<std::ffi::OsString>,
}

impl EndpointEnvironment {
    fn set(endpoint: &str) -> Self {
        let previous_endpoint = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT");
        let previous_trace_endpoint = std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
        let previous_batch_size = std::env::var_os("OTEL_BSP_MAX_EXPORT_BATCH_SIZE");
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint);
            std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
            std::env::set_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "1");
        }
        Self {
            previous_endpoint,
            previous_trace_endpoint,
            previous_batch_size,
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
            match &self.previous_batch_size {
                Some(value) => std::env::set_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", value),
                None => std::env::remove_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE"),
            }
        }
    }
}

struct BatchQueueEnvironment {
    previous_queue_size: Option<std::ffi::OsString>,
    previous_schedule_delay: Option<std::ffi::OsString>,
    previous_exporter_timeout: Option<std::ffi::OsString>,
    previous_trace_timeout: Option<std::ffi::OsString>,
}

impl BatchQueueEnvironment {
    fn set(queue_size: usize, schedule_delay_ms: u64) -> Self {
        let previous_queue_size = std::env::var_os("OTEL_BSP_MAX_QUEUE_SIZE");
        let previous_schedule_delay = std::env::var_os("OTEL_BSP_SCHEDULE_DELAY");
        let previous_exporter_timeout = std::env::var_os("OTEL_EXPORTER_OTLP_TIMEOUT");
        let previous_trace_timeout = std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT");
        unsafe {
            std::env::set_var("OTEL_BSP_MAX_QUEUE_SIZE", queue_size.to_string());
            std::env::set_var("OTEL_BSP_SCHEDULE_DELAY", schedule_delay_ms.to_string());
            std::env::set_var("OTEL_EXPORTER_OTLP_TIMEOUT", "120000");
            std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT");
        }
        Self {
            previous_queue_size,
            previous_schedule_delay,
            previous_exporter_timeout,
            previous_trace_timeout,
        }
    }
}

impl Drop for BatchQueueEnvironment {
    fn drop(&mut self) {
        unsafe {
            match &self.previous_queue_size {
                Some(value) => std::env::set_var("OTEL_BSP_MAX_QUEUE_SIZE", value),
                None => std::env::remove_var("OTEL_BSP_MAX_QUEUE_SIZE"),
            }
            match &self.previous_schedule_delay {
                Some(value) => std::env::set_var("OTEL_BSP_SCHEDULE_DELAY", value),
                None => std::env::remove_var("OTEL_BSP_SCHEDULE_DELAY"),
            }
            match &self.previous_exporter_timeout {
                Some(value) => std::env::set_var("OTEL_EXPORTER_OTLP_TIMEOUT", value),
                None => std::env::remove_var("OTEL_EXPORTER_OTLP_TIMEOUT"),
            }
            match &self.previous_trace_timeout {
                Some(value) => std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", value),
                None => std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT"),
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
                .route("/v1/traces", post(receive_span_body))
                .with_state(sender),
        )
        .await
        .unwrap();
    });

    let (otel_layer, provider) = cipherrun::telemetry::layer().unwrap();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(EnvFilter::new("info,sqlx::query=off")))
        .with(otel_layer);
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("otlp.integration");
        span.in_scope(|| {
            tracing::info!(event_name = "otlp.test", "export test span");
            tracing::debug!(
                target: "cipherrun::database",
                event_name = "database.debug.test",
                "database diagnostic"
            );
            tracing::event!(
                target: "sqlx::query",
                tracing::Level::WARN,
                db.statement = "SELECT 'otlp-query-secret'",
                elapsed_secs = 1.5,
                rows_returned = 1,
                "slow query"
            );
        });
    });
    tokio::task::spawn_blocking(move || provider.shutdown().unwrap())
        .await
        .unwrap();

    let payload =
        tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(5)).unwrap())
            .await
            .unwrap();
    let payload = String::from_utf8_lossy(&payload);
    assert!(payload.contains("otlp.test"), "{payload}");
    assert!(payload.contains("database.debug.test"), "{payload}");
    assert!(!payload.contains("otlp-query-secret"), "{payload}");
    collector.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn constructing_telemetry_layer_does_not_replace_the_global_provider() {
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

    let (_layer, provider) = cipherrun::telemetry::layer::<tracing_subscriber::Registry>().unwrap();
    opentelemetry::global::tracer("global-provider.integration")
        .in_span("unconfigured-global-provider", |_| {});
    tokio::task::spawn_blocking(move || provider.shutdown().unwrap())
        .await
        .unwrap();

    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    collector.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn otlp_collector_failure_is_reported_for_each_batch_without_panicking() {
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
    for span_index in 0..3 {
        tracing::info_span!("otlp.failure.integration", span_index)
            .in_scope(|| tracing::info!(event_name = "otlp.failure.test", "export failure test"));
    }
    let shutdown = tokio::task::spawn_blocking(move || provider.shutdown())
        .await
        .unwrap();

    assert!(shutdown.is_ok());
    let attempts = (0..12)
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
    assert_eq!(
        logs.matches("BatchSpanProcessor.ExportError").count(),
        3,
        "{logs}"
    );
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
        for span_index in 0..2 {
            tracing::info_span!("otlp.retry.integration", span_index)
                .in_scope(|| tracing::info!(event_name = "otlp.retry.test", "retry test span"));
        }
    });
    tokio::task::spawn_blocking(move || provider.shutdown().unwrap())
        .await
        .unwrap();

    let attempts = (0..6)
        .map(|_| receiver.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect::<Vec<_>>();
    assert!(
        attempts[..5]
            .iter()
            .all(|(_, status)| *status == StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(attempts[5].1, StatusCode::OK);
    assert!(attempts.iter().all(|(payload_size, _)| *payload_size > 0));
    assert_eq!(attempt.load(Ordering::SeqCst), 6);
    collector.abort();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "manual 60-second OTLP outage and recovery soak"]
async fn otlp_outage_soak_reports_queue_drops_and_recovers() {
    const QUEUE_SIZE: usize = 4;
    const SPANS_PER_INTERVAL: usize = 20;
    const OUTAGE_INTERVALS: usize = 12;

    let _environment_lock = OTLP_ENV_LOCK.lock().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let _environment = EndpointEnvironment::set(&endpoint);
    let _queue_environment = BatchQueueEnvironment::set(QUEUE_SIZE, 5_000);
    let (started_sender, mut started_receiver) = tokio::sync::mpsc::channel(1);
    let (completed_sender, mut completed_receiver) = tokio::sync::mpsc::channel(16);
    let recovery = Arc::new(tokio::sync::Semaphore::new(0));
    let collector_recovery = recovery.clone();
    let collector = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/traces", post(hold_spans_until_recovered))
                .with_state((collector_recovery, started_sender, completed_sender)),
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
    let dispatch = tracing::Dispatch::new(subscriber);

    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info_span!("otlp.outage.soak", span_index = 0)
            .in_scope(|| tracing::info!(event_name = "otlp.outage.soak", "outage soak span"));
    });
    let first_request = tokio::time::timeout(Duration::from_secs(5), started_receiver.recv())
        .await
        .expect("collector should receive the first export")
        .expect("collector channel should remain open");
    assert!(first_request > 0);

    for interval in 0..OUTAGE_INTERVALS {
        tracing::dispatcher::with_default(&dispatch, || {
            for span_index in 0..SPANS_PER_INTERVAL {
                tracing::info_span!("otlp.outage.soak", interval, span_index).in_scope(|| {
                    tracing::info!(event_name = "otlp.outage.soak", "outage soak span")
                });
            }
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    let during_outage = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(
        during_outage.contains("BatchSpanProcessor.SpanDroppingStarted"),
        "queue saturation must be reported during the outage: {during_outage}"
    );

    recovery.add_permits(QUEUE_SIZE + 1);
    for _ in 0..(QUEUE_SIZE + 1) {
        let (payload_size, status) =
            tokio::time::timeout(Duration::from_secs(15), completed_receiver.recv())
                .await
                .expect("queued spans should export after collector recovery")
                .expect("collector completion channel should remain open");
        assert!(payload_size > 0);
        assert_eq!(status, StatusCode::OK);
    }

    let shutdown_dispatch = dispatch.clone();
    let shutdown = tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&shutdown_dispatch, || provider.shutdown())
    })
    .await
    .unwrap();
    assert!(shutdown.is_ok());

    let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    let records = logs
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    let shutdown_warning = records
        .iter()
        .find(|record| record["fields"]["name"] == "BatchSpanProcessor.SpansDropped");
    assert!(
        shutdown_warning.is_some(),
        "shutdown must report the exact dropped span count"
    );
    let shutdown_warning = shutdown_warning.unwrap();
    let expected_drops = SPANS_PER_INTERVAL * OUTAGE_INTERVALS - QUEUE_SIZE;
    assert_eq!(
        shutdown_warning["fields"]["dropped_span_count"],
        expected_drops
    );
    assert_eq!(shutdown_warning["fields"]["max_queue_size"], QUEUE_SIZE);
    assert!(!logs.contains("collector-secret"));
    collector.abort();
}
