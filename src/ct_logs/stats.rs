// CT Logs Statistics Tracker
//
// Tracks performance and processing statistics

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// Per-source statistics
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
}

/// Thread-safe statistics tracker
pub struct StatsTracker {
    stats: Arc<Mutex<Stats>>,
}

impl StatsTracker {
    /// Create a new statistics tracker
    pub fn new() -> Self {
        let mut stats = Stats::default();
        stats.start_time = Some(Instant::now());

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
    pub fn update_source_stats(
        &self,
        source_id: &str,
        current_index: u64,
        tree_size: u64,
        fetch_time: Duration,
    ) {
        if let Ok(mut stats) = self.stats.lock() {
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

            // Update average fetch time
            let total_fetches = source_stats.successful_fetches;
            let old_avg = source_stats.avg_fetch_time_ms;
            let new_fetch_ms = fetch_time.as_millis() as u64;

            source_stats.avg_fetch_time_ms =
                ((old_avg * (total_fetches - 1)) + new_fetch_ms) / total_fetches;
        }
    }

    /// Increment source certificates processed
    pub fn increment_source_processed(&self, source_id: &str, count: u64) {
        if let Ok(mut stats) = self.stats.lock() {
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

    /// Increment source failed fetches
    pub fn increment_source_failures(&self, source_id: &str) {
        if let Ok(mut stats) = self.stats.lock() {
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
            && let Some(start_time) = stats.start_time {
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
        println!("Processing Time:      {} seconds", snapshot.processing_time_secs);

        if !snapshot.per_source.is_empty() {
            println!("\n=== Per-Source Statistics ===");
            for (source_id, source_stats) in &snapshot.per_source {
                println!("\nSource: {}", source_id);
                println!("  Processed:        {}", source_stats.certificates_processed);
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
}
