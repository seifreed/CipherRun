#![cfg(feature = "db-sqlite")]

use sqlx::ConnectOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::Instrument;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

struct CapturedOutputWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for CapturedOutput {
    type Writer = CapturedOutputWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedOutputWriter(self.0.clone())
    }
}

impl Write for CapturedOutputWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn sqlx_query_logging_omits_bound_secret_values() {
    let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(output.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("the dedicated integration-test process has no global subscriber");

    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(":memory:")
        .log_statements("debug".parse().expect("debug log level should parse"));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .expect("in-memory SQLx pool should connect");
    let secret = "sql-bound-secret-must-not-be-logged";
    sqlx::query("SELECT ? AS value WHERE 1 = 1 AND 2 = 2")
        .bind(secret)
        .fetch_one(&pool)
        .instrument(tracing::info_span!(
            "db.operation",
            request_id = "sqlx-correlation-test"
        ))
        .await
        .expect("bound query should succeed");

    let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    let event = logs
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| {
            event["target"] == "sqlx::query"
                && event["fields"]["db.statement"]
                    .as_str()
                    .is_some_and(|statement| statement.contains("SELECT ? AS value"))
        })
        .unwrap_or_else(|| panic!("SQLx query event should be captured; logs: {logs}"));
    assert_eq!(event["level"], "DEBUG");
    assert!(event["fields"]["elapsed_secs"].is_number());
    assert_eq!(event["fields"]["rows_returned"], 1, "logs: {logs}");
    assert!(event["fields"]["db.statement"].as_str().is_some());
    assert!(
        event["spans"]
            .as_array()
            .is_some_and(|spans| spans.iter().any(|span| {
                span["name"] == "db.operation" && span["request_id"] == "sqlx-correlation-test"
            })),
        "SQLx event should inherit its operation correlation span; logs: {logs}"
    );
    assert!(!logs.contains(secret));

    pool.close().await;
}
