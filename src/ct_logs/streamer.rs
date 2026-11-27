// CT Logs Streamer - Real-time certificate streaming engine
//
// Implements continuous streaming of CT logs with statistics

use super::{
    CtEntrySink, CtLogEntry, Result, client::CtClient, parser::Parser, sources::SourceManager,
    stats::StatsTracker,
};
use crate::error::TlsError;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info, info_span, warn};

/// Default batch size for fetching entries
const DEFAULT_BATCH_SIZE: u64 = 1000;

/// Maximum batch size allowed by CT logs
const MAX_BATCH_SIZE: u64 = 1000;

/// Default poll interval when caught up
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Configuration for CT log streaming
#[derive(Debug, Clone)]
pub struct CtConfig {
    /// Start from beginning of logs (index 0)
    pub start_from_beginning: bool,
    /// Custom start indices per log source (source_id -> index)
    pub custom_indices: HashMap<String, u64>,
    /// Poll interval when caught up with log
    pub poll_interval: Duration,
    /// Batch size for fetching entries
    pub batch_size: u64,
    /// Enable JSON output (one entry per line)
    pub json_output: bool,
    /// Silent mode (no stats output)
    pub silent: bool,
}

#[derive(Default)]
struct SpawnedTaskGuard(Vec<tokio::task::AbortHandle>);

impl SpawnedTaskGuard {
    fn track<T>(&mut self, task: &tokio::task::JoinHandle<T>) {
        self.0.push(task.abort_handle());
    }
}

impl Drop for SpawnedTaskGuard {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

impl Default for CtConfig {
    fn default() -> Self {
        Self {
            start_from_beginning: false,
            custom_indices: HashMap::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
            json_output: false,
            silent: false,
        }
    }
}

/// CT Log Streamer
pub struct CtStreamer {
    config: CtConfig,
    source_manager: SourceManager,
    stats: StatsTracker,
    shutdown: Arc<AtomicBool>,
}

impl CtStreamer {
    fn batch_end(current_index: u64, tree_size: u64, batch_size: u64) -> u64 {
        if tree_size == 0 {
            current_index
        } else {
            current_index
                .saturating_add(batch_size.saturating_sub(1))
                .min(tree_size.saturating_sub(1))
        }
    }

    fn normalized_config(config: CtConfig) -> Result<CtConfig> {
        if config.poll_interval.is_zero() {
            return Err(TlsError::InvalidInput {
                message: "CT logs poll interval must be greater than 0 seconds".to_string(),
            });
        }

        if config.batch_size == 0 || config.batch_size > MAX_BATCH_SIZE {
            return Err(TlsError::InvalidInput {
                message: format!("CT logs batch size must be between 1 and {MAX_BATCH_SIZE}"),
            });
        }
        Ok(config)
    }

    /// Create a new CT log streamer
    pub async fn new(config: CtConfig) -> Result<Self> {
        Self::new_with_source_list_url(
            config,
            super::sources::CT_LOG_LIST_URL,
            |url: String| async move { super::sources::ct_log_url_resolves_publicly(&url).await },
        )
        .await
    }

    async fn new_with_source_list_url<F, Fut>(
        config: CtConfig,
        source_list_url: &str,
        resolve: F,
    ) -> Result<Self>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = Result<bool>>,
    {
        let config = Self::normalized_config(config)?;

        // Initialize source manager and fetch log sources
        let mut source_manager = SourceManager::new();
        source_manager
            .fetch_sources_from(source_list_url, resolve)
            .await?;

        if source_manager.total_sources() == 0 {
            return Err(TlsError::ConfigError {
                message: "No CT log sources available".to_string(),
            });
        }

        info!(
            event_name = "ct_log.streamer.initialized",
            source_count = source_manager.total_sources(),
            "CT log streamer initialized"
        );

        // Initialize stats tracker
        let stats = StatsTracker::new();

        // Setup shutdown signal
        let shutdown = Arc::new(AtomicBool::new(false));

        Ok(Self {
            config,
            source_manager,
            stats,
            shutdown,
        })
    }

    /// Start streaming CT logs
    pub async fn start(&mut self) -> Result<()> {
        self.start_with_sink(None).await
    }

    /// Request graceful shutdown of all source streams.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Start streaming CT logs and deliver each parsed entry to an optional sink.
    pub async fn start_with_sink(&mut self, sink: Option<Arc<dyn CtEntrySink>>) -> Result<()> {
        let started = Instant::now();
        info!(
            event_name = "ct_log.streaming.started",
            "Starting CT log streaming"
        );

        let sources = self.source_manager.get_healthy_sources();
        if sources.is_empty() {
            error!(
                event_name = "ct_log.sources.unavailable",
                operation = "start_streaming",
                total_source_count = self.source_manager.total_sources(),
                healthy_source_count = 0,
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                error_type = "source_health",
                error_code = "no_healthy_sources",
                outcome = "failed",
                "CT log streaming has no healthy sources"
            );
            return Err(TlsError::ConfigError {
                message: "No healthy CT log sources".to_string(),
            });
        }

        let mut spawned_tasks = SpawnedTaskGuard::default();

        // Setup signal handler for graceful shutdown
        let shutdown_clone = Arc::clone(&self.shutdown);
        let signal_handle = crate::utils::task::spawn_with_current_span(async move {
            match crate::utils::shutdown::shutdown_signal().await {
                Ok(signal) => info!(event_name = "ct_log.shutdown.requested", signal),
                Err(_) => error!(
                    event_name = "ct_log.shutdown_signal.failed",
                    error_type = "signal_handler",
                    error_code = "signal_wait_failed",
                    "Failed to listen for shutdown signal"
                ),
            }
            shutdown_clone.store(true, Ordering::Release);
        });
        spawned_tasks.track(&signal_handle);

        // Create channel for certificate entries
        // Buffer size limited to prevent memory spike on burst of certificates
        let (tx, mut rx) = mpsc::channel::<CtLogEntry>(1000);

        // Spawn output handler
        let json_output = self.config.json_output;
        let sink_for_output = sink.clone();
        let output_handle = crate::utils::task::spawn_with_current_span(async move {
            while let Some(entry) = rx.recv().await {
                if let Some(sink) = &sink_for_output
                    && let Err(error) = sink.handle_entry(&entry).await
                {
                    warn!(
                        event_name = "ct_log.sink.failed",
                        source = %entry.log_source,
                        index = entry.index,
                        error_type = "sink_error",
                        error_code = error.observability_code(),
                        "CT entry sink rejected certificate"
                    );
                }
                if json_output {
                    // JSON output mode - one entry per line
                    match serde_json::to_string(&entry) {
                        Ok(json) => println!("{}", json),
                        Err(_) => error!(
                            event_name = "ct_log.output.serialize_failed",
                            source = %entry.log_source,
                            index = entry.index,
                            error_type = "serialization",
                            error_code = "serialization_failed",
                            "Failed to serialize CT entry for JSON output"
                        ),
                    }
                } else {
                    // Human-readable output
                    Self::print_entry(&entry);
                }
            }
        });
        spawned_tasks.track(&output_handle);

        info!(
            event_name = "ct_log.sources.streaming",
            source_count = sources.len(),
            "Streaming from healthy CT log sources"
        );

        // Spawn streaming task for each source
        let mut handles = Vec::new();

        for source in sources {
            let source_id = source.id.clone();
            let source_url = source.url.clone();
            let client = CtClient::new();
            let parser = Parser::new(source_id.clone());
            let tx = tx.clone();
            let stats = self.stats.clone();
            let shutdown = Arc::clone(&self.shutdown);
            let config = self.config.clone();

            let source_id_for_log = source_id.clone();
            let source_span = info_span!("ct_log.source", source = %source_id);
            let handle = tokio::spawn(
                async move {
                    Self::stream_source(
                        source_id, source_url, client, parser, tx, stats, shutdown, config,
                    )
                    .await
                }
                .instrument(source_span),
            );
            spawned_tasks.track(&handle);

            handles.push((source_id_for_log, handle));
        }

        // Drop the original sender so the output task can finish
        drop(tx);

        // Start stats reporting task if not silent
        let stats_handle = if !self.config.silent {
            let stats = self.stats.clone();
            let shutdown = Arc::clone(&self.shutdown);
            let handle = crate::utils::task::spawn_with_current_span(async move {
                Self::stats_reporter(stats, shutdown).await;
            });
            spawned_tasks.track(&handle);
            Some(handle)
        } else {
            None
        };

        // Wait for all streaming tasks to complete
        for (source_id, handle) in handles {
            if let Err(error) = handle.await {
                error!(
                    event_name = "ct_log.stream_task.failed",
                    source = %source_id,
                    error_type = if error.is_panic() { "panic" } else { "cancelled" },
                    error_code = if error.is_panic() {
                        "task_panicked"
                    } else {
                        "task_cancelled"
                    },
                    outcome = "failed",
                    "CT log streaming task failed"
                );
            }
        }

        // Wait for output task to complete
        if let Err(error) = output_handle.await {
            error!(
                event_name = "ct_log.output_task.failed",
                error_type = if error.is_panic() {
                    "panic"
                } else {
                    "cancelled"
                },
                error_code = if error.is_panic() {
                    "task_panicked"
                } else {
                    "task_cancelled"
                },
                outcome = "failed",
                "CT log output task failed"
            );
        }

        // Wait for stats reporter
        if let Some(handle) = stats_handle
            && let Err(error) = handle.await
        {
            error!(
                event_name = "ct_log.stats_task.failed",
                error_type = if error.is_panic() {
                    "panic"
                } else {
                    "cancelled"
                },
                error_code = if error.is_panic() {
                    "task_panicked"
                } else {
                    "task_cancelled"
                },
                outcome = "failed",
                "CT log stats reporter failed"
            );
        }

        if !signal_handle.is_finished() {
            signal_handle.abort();
        }
        if let Err(error) = signal_handle.await
            && !error.is_cancelled()
        {
            error!(
                event_name = "ct_log.shutdown_task.failed",
                error_type = "panic",
                error_code = "task_panicked",
                outcome = "failed",
                "CT log shutdown task failed"
            );
        }

        // Print final statistics
        if !self.config.silent {
            self.stats.print_stats();
        }

        info!(
            event_name = "ct_log.streaming.stopped",
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "stopped",
            "CT log streaming stopped"
        );
        Ok(())
    }

    /// Stream entries from a single source
    #[allow(clippy::too_many_arguments)]
    async fn stream_source(
        source_id: String,
        source_url: String,
        client: CtClient,
        parser: Parser,
        tx: mpsc::Sender<CtLogEntry>,
        stats: StatsTracker,
        shutdown: Arc<AtomicBool>,
        config: CtConfig,
    ) {
        let started = Instant::now();
        info!(event_name = "ct_log.source.started", source = %source_id, "Starting CT log source stream");

        // Determine starting index
        let mut current_index = if let Some(&custom_index) = config.custom_indices.get(&source_id) {
            info!(event_name = "ct_log.source.position.selected", source = %source_id, start_index = custom_index, outcome = "custom_index", "Selected CT log start position");
            custom_index
        } else if config.start_from_beginning {
            info!(event_name = "ct_log.source.position.selected", source = %source_id, start_index = 0_u64, outcome = "beginning", "Selected CT log start position");
            0
        } else {
            // Start from current tree size (now mode)
            let started = std::time::Instant::now();
            match client.get_tree_size(&source_url).await {
                Ok(tree_size) => {
                    info!(event_name = "ct_log.source.position.selected", source = %source_id, start_index = tree_size, duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), outcome = "current_tree_size", "Selected CT log start position");
                    tree_size
                }
                Err(error) => {
                    error!(event_name = "ct_log.tree_size.failed", source = %source_id, duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), error_type = "ct_log_request", error_code = error.observability_code(), outcome = "source_stopped", "Failed to get CT log tree size");
                    return;
                }
            }
        };

        // Streaming loop
        while !shutdown.load(Ordering::Acquire) {
            // Get current tree size
            let tree_size_started = std::time::Instant::now();
            let tree_size_duration_ms;
            let tree_size = match client.get_tree_size(&source_url).await {
                Ok(size) => {
                    tree_size_duration_ms =
                        u64::try_from(tree_size_started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    size
                }
                Err(error) => {
                    warn!(event_name = "ct_log.tree_size.failed", source = %source_id, duration_ms = u64::try_from(tree_size_started.elapsed().as_millis()).unwrap_or(u64::MAX), error_type = "ct_log_request", error_code = error.observability_code(), outcome = "retrying", "Failed to get CT log tree size");
                    stats.increment_source_failures(&source_id);
                    sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };

            // Check if we're caught up
            if current_index >= tree_size {
                debug!(event_name = "ct_log.source.caught_up", source = %source_id, current_index, tree_size, tree_size_duration_ms, "CT log source is caught up");
                sleep(config.poll_interval).await;
                continue;
            }

            // Calculate batch end (guard against underflow when tree_size is 0)
            // batch_end is inclusive, so we subtract 1 from batch_size to get exactly batch_size entries
            let batch_end = Self::batch_end(current_index, tree_size, config.batch_size);

            // Fetch batch
            let fetch_start = std::time::Instant::now();
            let entries = match client
                .get_entries(&source_url, current_index, batch_end)
                .await
            {
                Ok(entries) => entries,
                Err(error) => {
                    warn!(event_name = "ct_log.entries.failed", source = %source_id, start_index = current_index, end_index = batch_end, tree_size_duration_ms, duration_ms = u64::try_from(fetch_start.elapsed().as_millis()).unwrap_or(u64::MAX), error_type = "ct_log_request", error_code = error.observability_code(), outcome = "retrying", "Failed to fetch CT log entries");
                    stats.increment_source_failures(&source_id);
                    stats.increment_retries();
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let fetch_duration = fetch_start.elapsed();
            debug!(
                event_name = "ct_log.entries.fetched",
                source = %source_id,
                start_index = current_index,
                end_index = batch_end,
                entry_count = entries.len(),
                tree_size_duration_ms,
                duration_ms = u64::try_from(fetch_duration.as_millis()).unwrap_or(u64::MAX),
                "Fetched CT log entries"
            );

            // Update stats
            stats.update_source_stats(&source_id, current_index, tree_size, fetch_duration);

            // Process entries
            let mut processed_count = 0;
            for (offset, entry_response) in entries.iter().enumerate() {
                let entry_index =
                    current_index.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));

                // Parse entry
                match parser.parse_entry(entry_response, entry_index) {
                    Ok(entry) => {
                        processed_count += 1;
                        stats.increment_processed();

                        // Send to output channel
                        if tx.send(entry).await.is_err() {
                            warn!(
                                event_name = "ct_log.output_channel.closed",
                                source = %source_id,
                                "CT log output channel closed"
                            );
                            return;
                        }
                    }
                    Err(e) => {
                        debug!(
                            event_name = "ct_log.entry.parse_failed",
                            entry_index,
                            error_type = "TlsError",
                            error_code = e.observability_code(),
                            "Failed to parse CT log entry"
                        );
                    }
                }
            }

            stats.increment_source_processed(&source_id, processed_count);

            // Advance by the number of entries the log actually returned, NOT by the
            // requested range. CT logs (RFC 6962 get-entries) routinely cap responses
            // well below the requested batch size, so advancing to `batch_end + 1`
            // would permanently skip every entry the server did not return.
            if entries.is_empty() {
                warn!(
                    event_name = "ct_log.entries.empty",
                    requested_start = current_index,
                    requested_end = batch_end,
                    tree_size_duration_ms,
                    duration_ms = u64::try_from(fetch_duration.as_millis()).unwrap_or(u64::MAX),
                    outcome = "retrying",
                    "CT log returned no entries for the requested range; backing off"
                );
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            current_index =
                current_index.saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));

            // Small delay to avoid hammering the API
            sleep(Duration::from_millis(100)).await;
        }

        info!(event_name = "ct_log.source.stopped", source = %source_id, duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), outcome = "stopped", "Stopped CT log source stream");
    }

    /// Stats reporter task
    async fn stats_reporter(stats: StatsTracker, shutdown: Arc<AtomicBool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        while !shutdown.load(Ordering::Acquire) {
            interval.tick().await;
            stats.print_stats();
        }
    }

    /// Print a certificate entry (human-readable)
    fn print_entry(entry: &CtLogEntry) {
        println!(
            "\n[{}] Certificate from {} (index {})",
            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            entry.log_source,
            entry.index
        );

        if let Some(ref cn) = entry.certificate.subject_cn {
            println!("  CN: {}", cn);
        }

        if !entry.certificate.subject_an.is_empty() {
            println!("  SANs:");
            for san in &entry.certificate.subject_an {
                println!("    - {}", san);
            }
        }

        if let Some(ref issuer) = entry.certificate.issuer_cn {
            println!("  Issuer: {}", issuer);
        }

        println!("  Serial: {}", entry.certificate.serial);
        println!("  Type: {:?}", entry.cert_type);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct_logs::CertType;
    use crate::ct_logs::parser::Certificate;
    use axum::{Json, Router, extract::State, routing::get};
    use chrono::Utc;
    use std::io::Write;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::fmt::MakeWriter;

    async fn serve_ct_source_list(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local CT source-list fixture should bind");
        let address = listener
            .local_addr()
            .expect("local CT source-list fixture should have an address");
        tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("CT streamer should connect to the local source-list fixture");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("local CT source-list response should be written");
        });
        format!("http://{address}/log-list.json")
    }

    #[derive(Default)]
    struct EmptyEntriesState {
        shutdown: Arc<AtomicBool>,
        tree_size_requests: std::sync::atomic::AtomicUsize,
        entries_requests: std::sync::atomic::AtomicUsize,
    }

    async fn test_tree_size(
        State(state): State<Arc<EmptyEntriesState>>,
    ) -> Json<serde_json::Value> {
        state.tree_size_requests.fetch_add(1, Ordering::SeqCst);
        Json(serde_json::json!({
            "tree_size": 1,
            "timestamp": 0,
            "sha256_root_hash": "",
            "tree_head_signature": ""
        }))
    }

    async fn test_empty_entries(
        State(state): State<Arc<EmptyEntriesState>>,
    ) -> Json<serde_json::Value> {
        state.entries_requests.fetch_add(1, Ordering::SeqCst);
        state.shutdown.store(true, Ordering::Release);
        Json(serde_json::json!({ "entries": [] }))
    }

    async fn test_unavailable_entries(
        State(state): State<Arc<EmptyEntriesState>>,
    ) -> axum::http::StatusCode {
        state.entries_requests.fetch_add(1, Ordering::SeqCst);
        state.shutdown.store(true, Ordering::Release);
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    }

    async fn test_malformed_entry(
        State(state): State<Arc<EmptyEntriesState>>,
    ) -> Json<serde_json::Value> {
        state.entries_requests.fetch_add(1, Ordering::SeqCst);
        state.shutdown.store(true, Ordering::Release);
        Json(serde_json::json!({
            "entries": [{ "leaf_input": "%%%", "extra_data": "" }]
        }))
    }

    struct ValidEntryState {
        shutdown: Arc<AtomicBool>,
        leaf_input: String,
        entries_requests: std::sync::atomic::AtomicUsize,
    }

    #[derive(Default)]
    struct RejectingSink(Mutex<Vec<CtLogEntry>>);

    #[async_trait::async_trait]
    impl crate::ct_logs::CtEntrySink for RejectingSink {
        async fn handle_entry(&self, entry: &CtLogEntry) -> crate::ct_logs::Result<()> {
            self.0.lock().unwrap().push(entry.clone());
            Err(crate::TlsError::Other("private sink detail".to_string()))
        }
    }

    async fn test_valid_tree_size(
        State(_state): State<Arc<ValidEntryState>>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "tree_size": 1,
            "timestamp": 0,
            "sha256_root_hash": "",
            "tree_head_signature": ""
        }))
    }

    async fn test_valid_entry(
        State(state): State<Arc<ValidEntryState>>,
    ) -> Json<serde_json::Value> {
        state.entries_requests.fetch_add(1, Ordering::SeqCst);
        state.shutdown.store(true, Ordering::Release);
        Json(serde_json::json!({
            "entries": [{ "leaf_input": state.leaf_input, "extra_data": "" }]
        }))
    }

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedWriter(self.0.clone())
        }
    }

    impl Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn spawned_task_guard_aborts_detached_tasks_when_dropped() {
        let task = tokio::spawn(std::future::pending::<()>());
        let mut guard = SpawnedTaskGuard::default();
        guard.track(&task);

        drop(guard);

        assert!(
            task.await
                .expect_err("guard should abort the task")
                .is_cancelled()
        );
    }

    #[tokio::test]
    async fn no_healthy_sources_logs_safe_startup_failure() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();
        let mut streamer = CtStreamer {
            config: CtConfig::default(),
            source_manager: SourceManager::new(),
            stats: StatsTracker::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        let result = streamer
            .start()
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;
        assert!(result.is_err());

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let event = events
            .iter()
            .find(|event| event["fields"]["event_name"] == "ct_log.sources.unavailable")
            .expect("source health failure should be logged");
        assert_eq!(event["level"], "ERROR");
        assert_eq!(event["fields"]["operation"], "start_streaming");
        assert_eq!(event["fields"]["total_source_count"], 0);
        assert_eq!(event["fields"]["healthy_source_count"], 0);
        assert_eq!(event["fields"]["error_code"], "no_healthy_sources");
        assert_eq!(event["fields"]["outcome"], "failed");
        assert!(event["fields"]["duration_ms"].is_number());
        assert!(!output.contains("https://"));
    }

    #[tokio::test]
    async fn streamer_initializes_from_a_loopback_source_list_without_external_dns() {
        let source_list = serve_ct_source_list(
            r#"{"operators":[{"name":"Fixture operator","logs":[{"log_id":"fixture-log","url":"https://ct.example.test","state":{"usable":{}}}]}]}"#,
        )
        .await;

        let streamer =
            CtStreamer::new_with_source_list_url(CtConfig::default(), &source_list, |_| {
                std::future::ready(Ok(true))
            })
            .await
            .expect("a usable loopback-provided CT log should initialize the streamer");

        assert_eq!(streamer.source_manager.total_sources(), 1);
        assert_eq!(streamer.source_manager.healthy_sources_count(), 1);
        assert_eq!(streamer.config.batch_size, DEFAULT_BATCH_SIZE);
        assert!(!streamer.shutdown.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn streamer_rejects_a_source_list_without_usable_logs() {
        let source_list = serve_ct_source_list(r#"{"operators":[]}"#).await;

        let error =
            match CtStreamer::new_with_source_list_url(CtConfig::default(), &source_list, |_| {
                std::future::ready(Ok(true))
            })
            .await
            {
                Ok(_) => panic!("an empty CT source list must fail initialization"),
                Err(error) => error,
            };

        assert!(matches!(error, TlsError::ConfigError { .. }));
        assert!(error.to_string().contains("No CT log sources available"));
    }

    #[tokio::test]
    async fn public_streamer_constructor_rejects_invalid_config_before_network_access() {
        let error = match CtStreamer::new(CtConfig {
            poll_interval: Duration::ZERO,
            ..CtConfig::default()
        })
        .await
        {
            Ok(_) => panic!("a zero CT polling interval must fail initialization"),
            Err(error) => error,
        };

        assert!(matches!(error, TlsError::InvalidInput { .. }));
        assert!(
            error
                .to_string()
                .contains("poll interval must be greater than 0")
        );
    }

    #[tokio::test]
    async fn source_shutdown_logs_duration_and_outcome() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();
        let (tx, _rx) = mpsc::channel(1);
        let mut custom_indices = HashMap::new();
        custom_indices.insert("test-source".to_string(), 0);

        CtStreamer::stream_source(
            "test-source".to_string(),
            "https://unused.invalid".to_string(),
            CtClient::new(),
            Parser::new("test-source".to_string()),
            tx,
            StatsTracker::new(),
            Arc::new(AtomicBool::new(true)),
            CtConfig {
                custom_indices,
                ..CtConfig::default()
            },
        )
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;

        let output = output.0.lock().unwrap();
        let events: Vec<serde_json::Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("events should be JSON"))
            .collect();
        let event = events
            .iter()
            .find(|event| event["fields"]["event_name"] == "ct_log.source.stopped")
            .expect("source shutdown event should be emitted");
        assert_eq!(event["level"], "INFO");
        assert!(event["fields"]["duration_ms"].as_u64().is_some());
        assert_eq!(event["fields"]["outcome"], "stopped");
    }

    #[tokio::test]
    async fn initial_tree_size_failure_logs_duration_without_url() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();
        let (tx, _rx) = mpsc::channel(1);
        let future = CtStreamer::stream_source(
            "test-source".to_string(),
            "file:///private/sensitive-url".to_string(),
            CtClient::new(),
            Parser::new("test-source".to_string()),
            tx,
            StatsTracker::new(),
            Arc::new(AtomicBool::new(false)),
            CtConfig::default(),
        );
        future
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        let output = output.0.lock().unwrap();
        let events: Vec<serde_json::Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("events should be JSON"))
            .collect();
        let event = events
            .iter()
            .find(|event| event["fields"]["event_name"] == "ct_log.tree_size.failed")
            .expect("tree-size failure event should be emitted");
        assert_eq!(event["level"], "ERROR");
        assert_eq!(event["fields"]["event_name"], "ct_log.tree_size.failed");
        assert_eq!(event["fields"]["outcome"], "source_stopped");
        assert!(event["fields"]["duration_ms"].as_u64().is_some());
        assert!(!String::from_utf8_lossy(&output).contains("sensitive-url"));
    }

    #[tokio::test]
    async fn empty_ct_log_batch_retries_without_advancing_past_missing_entries() {
        let state = Arc::new(EmptyEntriesState::default());
        let app = Router::new()
            .route("/ct/v1/get-sth", get(test_tree_size))
            .route("/ct/v1/get-entries", get(test_empty_entries))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (tx, _rx) = mpsc::channel(1);

        CtStreamer::stream_source(
            "test-source".to_string(),
            format!("http://{address}"),
            CtClient::new(),
            Parser::new("test-source".to_string()),
            tx,
            StatsTracker::new(),
            Arc::clone(&state.shutdown),
            CtConfig {
                custom_indices: HashMap::from([("test-source".to_string(), 0)]),
                ..CtConfig::default()
            },
        )
        .await;

        assert_eq!(state.tree_size_requests.load(Ordering::SeqCst), 1);
        assert_eq!(state.entries_requests.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn failed_ct_log_batch_is_logged_and_retried_safely() {
        let state = Arc::new(EmptyEntriesState::default());
        let app = Router::new()
            .route("/ct/v1/get-sth", get(test_tree_size))
            .route("/ct/v1/get-entries", get(test_unavailable_entries))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(output.clone())
            .finish();
        let (tx, _rx) = mpsc::channel(1);

        CtStreamer::stream_source(
            "test-source".to_string(),
            format!("http://{address}"),
            CtClient::new(),
            Parser::new("test-source".to_string()),
            tx,
            StatsTracker::new(),
            Arc::clone(&state.shutdown),
            CtConfig {
                custom_indices: HashMap::from([("test-source".to_string(), 0)]),
                ..CtConfig::default()
            },
        )
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;

        assert_eq!(state.tree_size_requests.load(Ordering::SeqCst), 1);
        assert_eq!(state.entries_requests.load(Ordering::SeqCst), 3);
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(
            events.iter().any(|event| {
                event["fields"]["event_name"] == "ct_log.entries.failed"
                    && event["fields"]["outcome"] == "retrying"
                    && event["level"] == "WARN"
            }),
            "{output}"
        );
        assert!(!output.contains(&address.to_string()));
        server.abort();
    }

    #[tokio::test]
    async fn malformed_ct_log_entry_is_skipped_with_a_diagnostic_event() {
        let state = Arc::new(EmptyEntriesState::default());
        let app = Router::new()
            .route("/ct/v1/get-sth", get(test_tree_size))
            .route("/ct/v1/get-entries", get(test_malformed_entry))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(output.clone())
            .finish();
        let (tx, _rx) = mpsc::channel(1);

        CtStreamer::stream_source(
            "test-source".to_string(),
            format!("http://{address}"),
            CtClient::new(),
            Parser::new("test-source".to_string()),
            tx,
            StatsTracker::new(),
            Arc::clone(&state.shutdown),
            CtConfig {
                custom_indices: HashMap::from([("test-source".to_string(), 0)]),
                ..CtConfig::default()
            },
        )
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;

        assert_eq!(state.tree_size_requests.load(Ordering::SeqCst), 1);
        assert_eq!(state.entries_requests.load(Ordering::SeqCst), 1);
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("ct_log.entry.parse_failed"), "{output}");
        assert!(output.contains("ct_log.source.stopped"), "{output}");
        assert!(!output.contains("%%%"));
        server.abort();
    }

    #[tokio::test]
    async fn valid_ct_log_entry_is_delivered_to_the_consumer() {
        let state = valid_entry_state();
        let app = valid_entry_router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (tx, mut rx) = mpsc::channel(1);

        CtStreamer::stream_source(
            "test-source".to_string(),
            format!("http://{address}"),
            CtClient::new(),
            Parser::new("test-source".to_string()),
            tx,
            StatsTracker::new(),
            Arc::clone(&state.shutdown),
            CtConfig {
                custom_indices: HashMap::from([("test-source".to_string(), 0)]),
                ..CtConfig::default()
            },
        )
        .await;

        let entry = rx
            .try_recv()
            .expect("valid CT entry should reach the consumer");
        assert_eq!(entry.log_source, "test-source");
        assert_eq!(entry.index, 0);
        assert_eq!(
            entry.certificate.subject_cn.as_deref(),
            Some("ct-entry.example.test")
        );
        assert_eq!(state.entries_requests.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn closed_output_channel_stops_the_source_after_a_valid_entry() {
        let state = valid_entry_state();
        let app = valid_entry_router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(output.clone())
            .finish();

        CtStreamer::stream_source(
            "test-source".to_string(),
            format!("http://{address}"),
            CtClient::new(),
            Parser::new("test-source".to_string()),
            tx,
            StatsTracker::new(),
            Arc::clone(&state.shutdown),
            CtConfig {
                custom_indices: HashMap::from([("test-source".to_string(), 0)]),
                ..CtConfig::default()
            },
        )
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;

        assert_eq!(state.entries_requests.load(Ordering::SeqCst), 1);
        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("ct_log.output_channel.closed"), "{logs}");
        assert!(!logs.contains(&address.to_string()));
        server.abort();
    }

    fn valid_entry_state() -> Arc<ValidEntryState> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "ct-entry.example.test")
            .unwrap();
        let name = name.build();
        let mut certificate = X509Builder::new().unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let der = certificate.build().to_der().unwrap();
        let mut leaf = vec![0, 0];
        leaf.extend_from_slice(&0_u64.to_be_bytes());
        leaf.extend_from_slice(&0_u16.to_be_bytes());
        leaf.push(((der.len() >> 16) & 0xff) as u8);
        leaf.push(((der.len() >> 8) & 0xff) as u8);
        leaf.push((der.len() & 0xff) as u8);
        leaf.extend_from_slice(&der);

        Arc::new(ValidEntryState {
            shutdown: Arc::new(AtomicBool::new(false)),
            leaf_input: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, leaf),
            entries_requests: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn valid_entry_router(state: Arc<ValidEntryState>) -> Router {
        Router::new()
            .route("/ct/v1/get-sth", get(test_valid_tree_size))
            .route("/ct/v1/get-entries", get(test_valid_entry))
            .with_state(state)
    }

    #[tokio::test]
    async fn start_with_sink_drains_entries_and_redacts_sink_errors() {
        let state = valid_entry_state();
        let app = valid_entry_router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let source_manager = SourceManager::with_test_sources([super::super::sources::LogSource {
            id: "test-source".to_string(),
            description: "Local test CT log".to_string(),
            operator: "test".to_string(),
            url: format!("http://{address}"),
            key: None,
            mmd: None,
            tree_size: 0,
            usable: true,
            last_error: None,
            failure_count: 0,
        }]);
        let sink = Arc::new(RejectingSink::default());
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();
        let mut streamer = CtStreamer {
            config: CtConfig {
                custom_indices: HashMap::from([("test-source".to_string(), 0)]),
                silent: true,
                ..CtConfig::default()
            },
            source_manager,
            stats: StatsTracker::new(),
            shutdown: Arc::clone(&state.shutdown),
        };

        streamer
            .start_with_sink(Some(sink.clone()))
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await
            .expect("streaming should stop after the local log signals shutdown");

        let entries = sink.0.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].log_source, "test-source");
        assert_eq!(entries[0].index, 0);
        assert_eq!(state.entries_requests.load(Ordering::SeqCst), 1);
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("ct_log.streaming.started"), "{output}");
        assert!(output.contains("ct_log.sink.failed"), "{output}");
        assert!(output.contains("ct_log.streaming.stopped"), "{output}");
        assert!(!output.contains("private sink detail"), "{output}");
        server.abort();
    }

    #[test]
    fn test_config_defaults() {
        let config = CtConfig::default();
        assert!(!config.start_from_beginning);
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(config.poll_interval, DEFAULT_POLL_INTERVAL);
        assert!(!config.json_output);
        assert!(!config.silent);
    }

    #[test]
    fn test_config_default_custom_indices_empty() {
        let config = CtConfig::default();
        assert!(config.custom_indices.is_empty());
    }

    #[test]
    fn test_config_batch_size_validation() {
        let config = CtConfig {
            batch_size: 5000, // Too large
            ..Default::default()
        };

        let err = CtStreamer::normalized_config(config).expect_err("large batch should fail");
        assert!(err.to_string().contains("batch size"));
    }

    #[test]
    fn test_config_rejects_zero_batch_size() {
        let config = CtConfig {
            batch_size: 0,
            ..Default::default()
        };

        let err = CtStreamer::normalized_config(config).expect_err("zero batch should fail");
        assert!(err.to_string().contains("batch size"));
    }

    #[test]
    fn test_config_rejects_zero_poll_interval() {
        let config = CtConfig {
            poll_interval: Duration::ZERO,
            ..Default::default()
        };

        let err = CtStreamer::normalized_config(config).expect_err("zero interval should fail");
        assert!(err.to_string().contains("poll interval"));
    }

    #[test]
    fn test_batch_end_caps_at_tree_size() {
        assert_eq!(CtStreamer::batch_end(10, 15, 100), 14);
    }

    #[test]
    fn test_batch_end_saturates_current_index_overflow() {
        assert_eq!(
            CtStreamer::batch_end(u64::MAX - 5, u64::MAX, DEFAULT_BATCH_SIZE),
            u64::MAX - 1
        );
    }

    #[test]
    fn test_batch_end_handles_empty_tree() {
        assert_eq!(CtStreamer::batch_end(10, 0, DEFAULT_BATCH_SIZE), 10);
    }

    #[tokio::test]
    async fn test_stats_reporter_exits_when_shutdown() {
        let stats = StatsTracker::new();
        let shutdown = Arc::new(AtomicBool::new(true));
        CtStreamer::stats_reporter(stats, shutdown).await;
    }

    #[test]
    fn test_print_entry_no_panic() {
        let entry = CtLogEntry {
            log_source: "test".to_string(),
            index: 1,
            timestamp: Utc::now(),
            cert_type: CertType::X509Certificate,
            certificate: Certificate {
                der: vec![0x01, 0x02],
                subject_cn: Some("example.com".to_string()),
                subject_an: vec!["example.com".to_string()],
                issuer_cn: Some("issuer".to_string()),
                not_before: Utc::now(),
                not_after: Utc::now(),
                serial: "01".to_string(),
            },
        };

        CtStreamer::print_entry(&entry);
    }

    #[test]
    fn test_print_entry_without_optional_fields() {
        let entry = CtLogEntry {
            log_source: "test".to_string(),
            index: 2,
            timestamp: Utc::now(),
            cert_type: CertType::PreCertificate,
            certificate: Certificate {
                der: vec![0x01, 0x02],
                subject_cn: None,
                subject_an: Vec::new(),
                issuer_cn: None,
                not_before: Utc::now(),
                not_after: Utc::now(),
                serial: "02".to_string(),
            },
        };

        CtStreamer::print_entry(&entry);
    }

    #[test]
    fn test_config_custom_values_clone() {
        let mut indices = HashMap::new();
        indices.insert("log-a".to_string(), 42);

        let config = CtConfig {
            start_from_beginning: true,
            custom_indices: indices.clone(),
            poll_interval: Duration::from_secs(5),
            batch_size: 10,
            json_output: true,
            silent: true,
        };

        let cloned = config.clone();
        assert!(cloned.start_from_beginning);
        assert_eq!(cloned.poll_interval, Duration::from_secs(5));
        assert_eq!(cloned.batch_size, 10);
        assert!(cloned.json_output);
        assert!(cloned.silent);
        assert_eq!(cloned.custom_indices, indices);
    }

    #[test]
    fn test_config_flag_combinations() {
        let config = CtConfig {
            json_output: true,
            silent: false,
            ..Default::default()
        };

        assert!(config.json_output);
        assert!(!config.silent);
    }
}
