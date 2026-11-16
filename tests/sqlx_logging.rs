#![cfg(feature = "db-sqlite")]

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

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
async fn sqlx_query_logs_timing_without_bound_values() {
    let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(output.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("this integration test binary has one global subscriber");

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("SQLite pool should connect");
    let secret = "bound-value-must-not-be-logged";
    output.0.lock().unwrap().clear();

    let value: String = sqlx::query_scalar("SELECT ?")
        .bind(secret)
        .fetch_one(&pool)
        .await
        .expect("SQLite query should succeed");
    assert_eq!(value, secret);

    let output = output.0.lock().unwrap();
    let events: Vec<serde_json::Value> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("events should be JSON"))
        .collect();
    let event = events
        .iter()
        .find(|event| event["target"] == "sqlx::query")
        .expect("SQLx query event should be captured from its worker thread");
    assert_eq!(event["fields"]["summary"], "SELECT ?");
    assert!(event["fields"]["elapsed_secs"].as_f64().is_some());
    assert!(!String::from_utf8_lossy(&output).contains(secret));
}
