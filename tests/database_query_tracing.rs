use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::{Instrument, instrument::WithSubscriber};
use tracing_subscriber::fmt::MakeWriter;

struct Buffer(Arc<Mutex<Vec<u8>>>);
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buffer {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferWriter(self.0.clone())
    }
}

#[tokio::test]
async fn scan_query_span_correlates_without_recording_query_inputs() {
    use cipherrun::api::jobs::{DatabaseJobQueue, JobQueue, ScanJob};
    use cipherrun::db::{
        DatabasePool, config::DatabaseConfig, migrations::run_migrations,
        repositories::ScanRepositoryImpl, traits::ScanRepository,
    };

    let directory = tempfile::tempdir().unwrap();
    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_ansi(false)
        .with_writer(Buffer(output.clone()))
        .finish();

    async {
        let config = DatabaseConfig::sqlite(directory.path().join("observability.db"));
        let pool = DatabasePool::new(&config).await.unwrap();
        run_migrations(&pool).await.unwrap();
        let repo = ScanRepositoryImpl::new(pool.clone());
        let request = tracing::info_span!("http.request", request_id = "db-query-test");

        repo.get_scan_by_id(i64::MAX)
            .instrument(request)
            .await
            .unwrap();
        let queue = DatabaseJobQueue::new(Arc::new(pool.clone()), 10, None);
        let request = tracing::info_span!("http.request", request_id = "db-queue-test");
        queue
            .enqueue(ScanJob::new(
                "db-job-target-secret.example:443".to_string(),
                Default::default(),
                None,
            ))
            .instrument(request)
            .await
            .unwrap();
        pool.close().await;
    }
    .with_subscriber(tracing::Dispatch::new(subscriber))
    .await;

    let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(
        output.contains("operation=\"scan.get_by_id\""),
        "{output:?}"
    );
    assert!(
        output.contains("request_id=\"db-query-test\""),
        "{output:?}"
    );
    assert!(!output.contains(&i64::MAX.to_string()), "{output:?}");
    assert!(!output.contains("SELECT"), "{output:?}");
    assert!(
        !output.contains("db-job-target-secret.example"),
        "{output:?}"
    );
    assert!(output.contains("job_queue.enqueue"), "{output:?}");
    assert!(
        output.contains("request_id=\"db-queue-test\""),
        "{output:?}"
    );
}
