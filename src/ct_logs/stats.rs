// CT Logs Statistics Tracker
//
// Tracks performance and processing statistics

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum number of per-source stats to track
/// Prevents unbounded memory growth from many unique CT log sources
const MAX_SOURCES: usize = 1000;

/// Statistics for CT log streaming
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    /// Total certificates processed
    pub total_processed: u64,
    /// Unique certificates (post-deduplication)
    pub unique_certificates: u64,
    /// Duplicates filtered
    pub duplicates_filtered: u64,
    /// Total retry attempts
    pub retry_attempts: u64,
    /// Per-source statistics (bounded to prevent memory exhaustion)
    pub per_source: HashMap<String, SourceStats>,
    /// Start time
    #[serde(skip)]
    pub start_time: Option<Instant>,
    /// Total processing time in seconds
    pub processing_time_secs: u64,
}

/// Per-source statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceStats {
    /// Source ID
    pub source_id: String,
    /// Certificates processed from this source
    pub certificates_processed: u64,
    /// Current index in log
    pub current_index: u64,
    /// Tree size
    pub tree_size: u64,
    /// Number of successful fetches
    pub successful_fetches: u64,
    /// Number of failed fetches
    pub failed_fetches: u64,
    /// Average fetch time in milliseconds
    pub avg_fetch_time_ms: u64,
    /// Total fetch time in milliseconds (for accurate average calculation)
    pub total_fetch_time_ms: u64,
}

/// Thread-safe statistics tracker
pub struct StatsTracker {
    stats: Arc<Mutex<Stats>>,
}

impl StatsTracker {
    /// Create a new statistics tracker
    pub fn new() -> Self {
        let stats = Stats {
            start_time: Some(Instant::now()),
            ..Default::default()
        };

        Self {
            stats: Arc::new(Mutex::new(stats)),
        }
    }

    /// Increment total processed count
    pub fn increment_processed(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.total_processed += 1;
        }
    }

    /// Increment unique certificates count
    pub fn increment_unique(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.unique_certificates += 1;
        }
    }

    /// Increment duplicates filtered count
    pub fn increment_duplicates(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.duplicates_filtered += 1;
        }
    }

    /// Increment retry attempts
    pub fn increment_retries(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.retry_attempts += 1;
        }
    }

    /// Update source statistics
    ///
    /// Note: Per-source stats are bounded to MAX_SOURCES to prevent unbounded memory growth.
    /// If the limit is reached, stats for new sources are not tracked (but global stats still work).
    pub fn update_source_stats(
        &self,
        source_id: &str,
        current_index: u64,
        tree_size: u64,
        fetch_time: Duration,
    ) {
        if let Ok(mut stats) = self.stats.lock() {
            // Check if we should track this source
            // Either it already exists, or we have room for new sources
            let should_track =
                stats.per_source.contains_key(source_id) || stats.per_source.len() < MAX_SOURCES;

            if !should_track {
                // Skip tracking for new sources when at capacity
                // Global stats (total_processed, etc.) are still updated
                return;
            }

            let source_stats = stats
                .per_source
                .entry(source_id.to_string())
                .or_insert_with(|| SourceStats {
                    source_id: source_id.to_string(),
                    ..Default::default()
                });

            source_stats.current_index = current_index;
            source_stats.tree_size = tree_size;
            source_stats.successful_fetches += 1;

            // Update average fetch time using running sum for accuracy
            let new_fetch_ms = fetch_time.as_millis() as u64;
            source_stats.total_fetch_time_ms = source_stats
                .total_fetch_time_ms
                .saturating_add(new_fetch_ms);
            source_stats.avg_fetch_time_ms = source_stats
                .total_fetch_time_ms
                .checked_div(source_stats.successful_fetches)
                .unwrap_or(0);
        }
    }

    /// Increment source certificates processed
    ///
    /// Note: Per-source stats are bounded to MAX_SOURCES. New sources beyond
    /// the limit will not have their per-source stats tracked.
    pub fn increment_source_processed(&self, source_id: &str, count: u64) {
        if let Ok(mut stats) = self.stats.lock() {
            // Only track if source exists or we have capacity
            if let Some(source_stats) = stats.per_source.get_mut(source_id) {
                source_stats.certificates_processed += count;
            } else if stats.per_source.len() < MAX_SOURCES {
                // Create new entry only if under capacity
                let source_stats = stats
                    .per_source
                    .entry(source_id.to_string())
                    .or_insert_with(|| SourceStats {
                        source_id: source_id.to_string(),
                        ..Default::default()
                    });
                source_stats.certificates_processed += count;
            }
        }
    }

    /// Increment source failed fetches
    pub fn increment_source_failures(&self, source_id: &str) {
        if let Ok(mut stats) = self.stats.lock() {
            // Only update existing entries or create new ones if under capacity
            if let Some(source_stats) = stats.per_source.get_mut(source_id) {
                source_stats.failed_fetches += 1;
            } else if stats.per_source.len() < MAX_SOURCES {
                let source_stats = stats
                    .per_source
                    .entry(source_id.to_string())
                    .or_insert_with(|| SourceStats {
                        source_id: source_id.to_string(),
                        ..Default::default()
                    });
                source_stats.failed_fetches += 1;
            }
        }
    }

    /// Get current statistics snapshot
    pub fn get_snapshot(&self) -> Stats {
        if let Ok(mut stats) = self.stats.lock() {
            // Update processing time
            if let Some(start_time) = stats.start_time {
                stats.processing_time_secs = start_time.elapsed().as_secs();
            }

            stats.clone()
        } else {
            Stats::default()
        }
    }

    /// Get processing rate (certificates per second)
    pub fn get_processing_rate(&self) -> f64 {
        if let Ok(stats) = self.stats.lock()
            && let Some(start_time) = stats.start_time
        {
            let elapsed_secs = start_time.elapsed().as_secs_f64();
            if elapsed_secs > 0.0 {
                return stats.total_processed as f64 / elapsed_secs;
            }
        }
        0.0
    }

    /// Print statistics to stdout
    pub fn print_stats(&self) {
        let snapshot = self.get_snapshot();
        let rate = self.get_processing_rate();

        println!("\n=== CT Logs Streaming Statistics ===");
        println!("Total Processed:      {}", snapshot.total_processed);
        println!("Unique Certificates:  {}", snapshot.unique_certificates);
        println!("Duplicates Filtered:  {}", snapshot.duplicates_filtered);
        println!(
            "Deduplication Rate:   {:.2}%",
            if snapshot.total_processed > 0 {
                (snapshot.duplicates_filtered as f64 / snapshot.total_processed as f64) * 100.0
            } else {
                0.0
            }
        );
        println!("Processing Rate:      {:.2} certs/sec", rate);
        println!("Retry Attempts:       {}", snapshot.retry_attempts);
        println!(
            "Processing Time:      {} seconds",
            snapshot.processing_time_secs
        );

        if !snapshot.per_source.is_empty() {
            println!("\n=== Per-Source Statistics ===");
            for (source_id, source_stats) in &snapshot.per_source {
                println!("\nSource: {}", source_id);
                println!(
                    "  Processed:        {}",
                    source_stats.certificates_processed
                );
                println!("  Current Index:    {}", source_stats.current_index);
                println!("  Tree Size:        {}", source_stats.tree_size);
                println!(
                    "  Progress:         {:.2}%",
                    if source_stats.tree_size > 0 {
                        (source_stats.current_index as f64 / source_stats.tree_size as f64) * 100.0
                    } else {
                        0.0
                    }
                );
                println!("  Successful Fetches: {}", source_stats.successful_fetches);
                println!("  Failed Fetches:   {}", source_stats.failed_fetches);
                println!("  Avg Fetch Time:   {} ms", source_stats.avg_fetch_time_ms);
            }
        }

        println!("\n=====================================\n");
    }
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for StatsTracker {
    fn clone(&self) -> Self {
        Self {
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_tracker_creation() {
        let tracker = StatsTracker::new();
        let snapshot = tracker.get_snapshot();

        assert_eq!(snapshot.total_processed, 0);
        assert_eq!(snapshot.unique_certificates, 0);
        assert_eq!(snapshot.duplicates_filtered, 0);
        assert!(snapshot.start_time.is_some());
    }

    #[test]
    fn test_increment_counters() {
        let tracker = StatsTracker::new();

        tracker.increment_processed();
        tracker.increment_processed();
        tracker.increment_unique();

        let snapshot = tracker.get_snapshot();
        assert_eq!(snapshot.total_processed, 2);
        assert_eq!(snapshot.unique_certificates, 1);
    }

    #[test]
    fn test_processing_rate() {
        let tracker = StatsTracker::new();

        // Process some items
        for _ in 0..10 {
            tracker.increment_processed();
        }

        let rate = tracker.get_processing_rate();
        assert!(rate >= 0.0);
    }

    #[test]
    fn test_source_stats() {
        let tracker = StatsTracker::new();

        tracker.update_source_stats("test-log", 100, 1000, Duration::from_millis(500));
        tracker.increment_source_processed("test-log", 10);

        let snapshot = tracker.get_snapshot();
        assert!(snapshot.per_source.contains_key("test-log"));

        let source_stats = &snapshot.per_source["test-log"];
        assert_eq!(source_stats.current_index, 100);
        assert_eq!(source_stats.tree_size, 1000);
        assert_eq!(source_stats.certificates_processed, 10);
        assert_eq!(source_stats.successful_fetches, 1);
    }

    #[test]
    fn test_clone_tracker() {
        let tracker1 = StatsTracker::new();
        tracker1.increment_processed();

        let tracker2 = tracker1.clone();
        tracker2.increment_processed();

        // Both trackers should share the same stats
        let snapshot = tracker1.get_snapshot();
        assert_eq!(snapshot.total_processed, 2);
    }

    #[test]
    fn test_source_stats_average_and_failures() {
        let tracker = StatsTracker::new();

        tracker.update_source_stats("log-a", 10, 100, Duration::from_millis(100));
        tracker.update_source_stats("log-a", 20, 100, Duration::from_millis(300));
        tracker.increment_source_failures("log-a");
        tracker.increment_retries();

        let snapshot = tracker.get_snapshot();
        let source = &snapshot.per_source["log-a"];
        assert_eq!(source.successful_fetches, 2);
        assert_eq!(source.avg_fetch_time_ms, 200);
        assert_eq!(source.failed_fetches, 1);
        assert_eq!(snapshot.retry_attempts, 1);
    }
}
