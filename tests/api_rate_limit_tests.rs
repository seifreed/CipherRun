use axum::http::StatusCode;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

mod common;

#[tokio::test]
async fn test_rate_limit_requests_within_limit_succeed() {
    let app = common::api::test_api_router();

    for _ in 0..5 {
        let (status, _) =
            common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-user-key"), None).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn test_rate_limit_headers_present() {
    let app = common::api::test_api_router();
    let request = common::api::authenticated_request("GET", "/api/v1/stats", "test-user-key");
    let response = app.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert!(headers.contains_key("x-ratelimit-limit"));
    assert!(headers.contains_key("x-ratelimit-remaining"));
    assert!(headers.contains_key("x-ratelimit-reset"));
}

#[tokio::test]
async fn test_rate_limit_admin_bypasses_limit() {
    let app = common::api::test_api_router_with_rate_limit(2);

    for i in 0..10 {
        let (status, _) =
            common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-admin-key"), None)
                .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Admin request {} should succeed despite rate limit",
            i + 1
        );
    }
}

#[tokio::test]
async fn test_rate_limit_exceeds_limit_returns_429() {
    let app = common::api::test_api_router_with_rate_limit(3);

    for _ in 0..3 {
        let (status, _) =
            common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-user-key"), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, body) =
        common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-user-key"), None).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "Rate limit exceeded");
    assert_eq!(body["limit"], 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual 30-second API and logging load soak"]
async fn api_logging_load_soak_accounts_for_requests_and_events() {
    const PRODUCERS: usize = 8;
    const SOAK: Duration = Duration::from_secs(30);
    const REQUEST_INTERVAL: Duration = Duration::from_millis(20);

    let directory = tempfile::tempdir().unwrap();
    let file = tracing_appender::rolling::never(directory.path(), "api-load.jsonl");
    let (writer, worker_guard) = tracing_appender::non_blocking(file);
    let dropped_lines = writer.error_counter();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(writer)
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let app = common::api::test_api_router();
    let attempted = Arc::new(AtomicUsize::new(0));
    let durations = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let deadline = started + SOAK;

    let producers = (0..PRODUCERS)
        .map(|_| {
            let app = app.clone();
            let dispatch = dispatch.clone();
            let attempted = attempted.clone();
            let durations = durations.clone();
            tokio::spawn(async move {
                while Instant::now() < deadline {
                    let request =
                        common::api::authenticated_request("GET", "/health", "test-admin-key");
                    let request_started = Instant::now();
                    let response = app
                        .clone()
                        .oneshot(request)
                        .with_subscriber(dispatch.clone())
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    assert!(response.headers().contains_key("x-request-id"));
                    durations
                        .lock()
                        .unwrap()
                        .push(request_started.elapsed().as_micros() as u64);
                    attempted.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(REQUEST_INTERVAL).await;
                }
            })
        })
        .collect::<Vec<_>>();

    for producer in producers {
        producer.await.unwrap();
    }
    drop(dispatch);
    drop(worker_guard);

    let log = std::fs::read_to_string(directory.path().join("api-load.jsonl")).unwrap();
    let events = log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let request_events = events
        .iter()
        .filter(|event| event["fields"]["event_name"] == "api.request.completed")
        .count();
    let attempted = attempted.load(Ordering::Relaxed);
    let dropped = dropped_lines.dropped_lines();
    let mut durations = durations.lock().unwrap().clone();
    durations.sort_unstable();
    let p95_micros = durations[(durations.len() - 1) * 95 / 100];

    assert_eq!(attempted, durations.len());
    assert_eq!(attempted, request_events + dropped);
    assert_eq!(dropped, 0, "API logging soak dropped {dropped} events");
    assert!(events.iter().all(|event| {
        event["fields"]["event_name"] == "api.request.completed"
            && event["fields"]["duration_ms"].is_number()
            && event["fields"]["request_id"].is_string()
    }));
    assert!(!log.contains("test-admin-key"));

    eprintln!(
        "api logging soak: duration_ms={}, attempted={}, written={}, dropped={}, requests_per_second={}, p95_request_us={}",
        started.elapsed().as_millis(),
        attempted,
        request_events,
        dropped,
        (attempted as u128 * 1_000) / started.elapsed().as_millis().max(1),
        p95_micros,
    );
}
