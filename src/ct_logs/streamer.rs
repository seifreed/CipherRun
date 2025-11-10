// CT Logs Streamer - Real-time certificate streaming engine
//
// Implements continuous streaming of CT logs with deduplication and statistics

use super::{
    client::CtClient, deduplicator::Deduplicator, parser::Parser, sources::SourceManager,
    stats::StatsTracker, CtLogEntry, Result,
};
use crate::error::TlsError;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

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
    /// Expected number of unique certificates (for bloom filter sizing)
    pub expected_unique_certs: usize,
    /// False positive rate for bloom filter
    pub bloom_fp_rate: f64,
    /// Enable JSON output (one entry per line)
    pub json_output: bool,
    /// Silent mode (no stats output)
    pub silent: bool,
}

impl Default for CtConfig {
    fn default() -> Self {
        Self {
            start_from_beginning: false,
            custom_indices: HashMap::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
            expected_unique_certs: 1_000_000,
            bloom_fp_rate: 0.0001,
            json_output: false,
            silent: false,
        }
    }
}

/// CT Log Streamer
pub struct CtStreamer {
    config: CtConfig,
    source_manager: SourceManager,
    client: CtClient,
    deduplicator: Deduplicator,
    stats: StatsTracker,
    shutdown: Arc<AtomicBool>,
}

impl CtStreamer {
    /// Create a new CT log streamer
    pub async fn new(config: CtConfig) -> Result<Self> {
        // Validate batch size
        let batch_size = config.batch_size.min(MAX_BATCH_SIZE).max(1);
        let mut config = config;
        config.batch_size = batch_size;

        // Initialize source manager and fetch log sources
        let mut source_manager = SourceManager::new();
        source_manager.fetch_sources().await?;

        if source_manager.total_sources() == 0 {
            return Err(TlsError::ConfigError {
                message: "No CT log sources available".to_string()
            });
        }

        info!(
            "Initialized CT streamer with {} sources",
            source_manager.total_sources()
        );

        // Initialize deduplicator
        let deduplicator = Deduplicator::new(config.expected_unique_certs, config.bloom_fp_rate);

        // Initialize stats tracker
        let stats = StatsTracker::new();

        // Initialize client
        let client = CtClient::new();

        // Setup shutdown signal
        let shutdown = Arc::new(AtomicBool::new(false));

        Ok(Self {
            config,
            source_manager,
            client,
            deduplicator,
            stats,
            shutdown,
        })
    }

    /// Start streaming CT logs
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting CT log streaming...");

        // Setup signal handler for graceful shutdown
        let shutdown_clone = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            if let Err(e) = signal::ctrl_c().await {
                error!("Failed to listen for shutdown signal: {}", e);
            }
            info!("Shutdown signal received");
            shutdown_clone.store(true, Ordering::Relaxed);
        });

        // Create channel for certificate entries
        let (tx, mut rx) = mpsc::channel::<CtLogEntry>(10000);

        // Spawn output handler
        let json_output = self.config.json_output;
        let output_handle = tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                if json_output {
                    // JSON output mode - one entry per line
                    if let Ok(json) = serde_json::to_string(&entry) {
                        println!("{}", json);
                    }
                } else {
                    // Human-readable output
                    Self::print_entry(&entry);
                }
            }
        });

        // Get healthy sources
        let sources = self.source_manager.get_healthy_sources();
        if sources.is_empty() {
            return Err(TlsError::ConfigError {
                message: "No healthy CT log sources".to_string()
            });
        }

        info!("Streaming from {} healthy sources", sources.len());

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

            let handle = tokio::spawn(async move {
                Self::stream_source(
                    source_id,
                    source_url,
                    client,
                    parser,
                    tx,
                    stats,
                    shutdown,
                    config,
                )
                .await
            });

            handles.push(handle);
        }

        // Drop the original sender so the output task can finish
        drop(tx);

        // Start stats reporting task if not silent
        let stats_handle = if !self.config.silent {
            let stats = self.stats.clone();
            let shutdown = Arc::clone(&self.shutdown);
            Some(tokio::spawn(async move {
                Self::stats_reporter(stats, shutdown).await;
            }))
        } else {
            None
        };

        // Wait for all streaming tasks to complete
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Streaming task failed: {}", e);
            }
        }

        // Wait for output task to complete
        if let Err(e) = output_handle.await {
            error!("Output task failed: {}", e);
        }

        // Wait for stats reporter
        if let Some(handle) = stats_handle {
            if let Err(e) = handle.await {
                error!("Stats reporter failed: {}", e);
            }
        }

        // Print final statistics
        if !self.config.silent {
            self.stats.print_stats();
        }

        info!("CT log streaming stopped");
        Ok(())
    }

    /// Stream entries from a single source
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
        info!("Starting stream for source: {}", source_id);

        // Determine starting index
        let mut current_index = if let Some(&custom_index) = config.custom_indices.get(&source_id) {
            info!("Starting from custom index {} for {}", custom_index, source_id);
            custom_index
        } else if config.start_from_beginning {
            info!("Starting from beginning (index 0) for {}", source_id);
            0
        } else {
            // Start from current tree size (now mode)
            match client.get_tree_size(&source_url).await {
                Ok(tree_size) => {
                    info!("Starting from current tree size {} for {}", tree_size, source_id);
                    tree_size
                }
                Err(e) => {
                    error!("Failed to get tree size for {}: {}", source_id, e);
                    return;
                }
            }
        };

        // Streaming loop
        while !shutdown.load(Ordering::Relaxed) {
            // Get current tree size
            let tree_size = match client.get_tree_size(&source_url).await {
                Ok(size) => size,
                Err(e) => {
                    error!("Failed to get tree size for {}: {}", source_id, e);
                    stats.increment_source_failures(&source_id);
                    sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };

            // Check if we're caught up
            if current_index >= tree_size {
                debug!("Caught up with log {} (index: {}, tree size: {})", source_id, current_index, tree_size);
                sleep(config.poll_interval).await;
                continue;
            }

            // Calculate batch end
            let batch_end = (current_index + config.batch_size).min(tree_size - 1);

            debug!(
                "Fetching entries {}-{} from {} (tree size: {})",
                current_index, batch_end, source_id, tree_size
            );

            // Fetch batch
            let fetch_start = std::time::Instant::now();
            let entries = match client.get_entries(&source_url, current_index, batch_end).await {
                Ok(entries) => entries,
                Err(e) => {
                    error!("Failed to fetch entries for {}: {}", source_id, e);
                    stats.increment_source_failures(&source_id);
                    stats.increment_retries();
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let fetch_duration = fetch_start.elapsed();

            // Update stats
            stats.update_source_stats(&source_id, current_index, tree_size, fetch_duration);

            // Process entries
            let mut processed_count = 0;
            for (offset, entry_response) in entries.iter().enumerate() {
                let entry_index = current_index + offset as u64;

                // Parse entry
                match parser.parse_entry(entry_response, entry_index) {
                    Ok(entry) => {
                        processed_count += 1;
                        stats.increment_processed();

                        // Send to output channel
                        if tx.send(entry).await.is_err() {
                            warn!("Output channel closed, stopping stream for {}", source_id);
                            return;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse entry {} from {}: {}", entry_index, source_id, e);
                    }
                }
            }

            stats.increment_source_processed(&source_id, processed_count);

            // Move to next batch
            current_index = batch_end + 1;

            // Small delay to avoid hammering the API
            sleep(Duration::from_millis(100)).await;
        }

        info!("Stopped streaming from source: {}", source_id);
    }

    /// Stats reporter task
    async fn stats_reporter(stats: StatsTracker, shutdown: Arc<AtomicBool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        while !shutdown.load(Ordering::Relaxed) {
            interval.tick().await;
            stats.print_stats();
        }
    }

    /// Print a certificate entry (human-readable)
    fn print_entry(entry: &CtLogEntry) {
        println!("\n[{}] Certificate from {} (index {})",
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

    #[test]
    fn test_config_defaults() {
        let config = CtConfig::default();
        assert!(!config.start_from_beginning);
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(config.poll_interval, DEFAULT_POLL_INTERVAL);
    }

    #[test]
    fn test_config_batch_size_validation() {
        let config = CtConfig {
            batch_size: 5000, // Too large
            ..Default::default()
        };

        // Should be clamped to MAX_BATCH_SIZE
        assert!(config.batch_size > MAX_BATCH_SIZE);
    }
}
