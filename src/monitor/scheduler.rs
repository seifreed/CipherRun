// Scheduling Engine - Manages scan intervals and timing

use crate::monitor::inventory::MonitoredDomain;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use std::collections::HashMap;

/// Scheduling engine for managing domain scan intervals
pub struct SchedulingEngine {
    next_scan_times: HashMap<String, DateTime<Utc>>,
    jitter_percent: u8,
}

impl SchedulingEngine {
    /// Create new scheduling engine
    pub fn new() -> Self {
        Self {
            next_scan_times: HashMap::new(),
            jitter_percent: 10, // ±10% jitter by default
        }
    }

    /// Create with custom jitter percentage
    pub fn with_jitter(mut self, jitter_percent: u8) -> Self {
        self.jitter_percent = jitter_percent.min(50); // Cap at 50%
        self
    }

    /// Get domains that are due for scanning
    pub fn get_domains_to_scan<'a>(
        &mut self,
        domains: &'a [MonitoredDomain],
    ) -> Vec<&'a MonitoredDomain> {
        let now = Utc::now();
        let mut due_domains = Vec::new();

        for domain in domains {
            let identifier = domain.identifier();

            // Check if domain is due for scan
            let is_due = if let Some(next_scan) = self.next_scan_times.get(&identifier) {
                now >= *next_scan
            } else {
                // First scan - schedule immediately
                true
            };

            if is_due {
                due_domains.push(domain);
                // Schedule next scan
                self.schedule_next_scan_internal(&identifier, domain.interval_seconds);
            }
        }

        due_domains
    }

    /// Schedule next scan for a domain
    pub fn schedule_next_scan(&mut self, hostname: &str, interval_seconds: u64) {
        self.schedule_next_scan_internal(hostname, interval_seconds);
    }

    /// Internal method to schedule next scan with jitter
    fn schedule_next_scan_internal(&mut self, identifier: &str, interval_seconds: u64) {
        let interval_with_jitter = self.add_jitter(Duration::seconds(interval_seconds as i64));
        let next_scan = Utc::now() + interval_with_jitter;

        self.next_scan_times
            .insert(identifier.to_string(), next_scan);
    }

    /// Add jitter to duration to prevent thundering herd
    ///
    /// Adds random variation of ±jitter_percent to the duration
    fn add_jitter(&self, duration: Duration) -> Duration {
        let mut rng = rand::thread_rng();

        // Calculate jitter range
        let seconds = duration.num_seconds();
        let jitter_range = (seconds * self.jitter_percent as i64) / 100;

        // Random jitter between -jitter_range and +jitter_range
        let jitter = rng.gen_range(-jitter_range..=jitter_range);

        Duration::seconds(seconds + jitter)
    }

    /// Get next scan time for a domain
    pub fn next_scan_time(&self, identifier: &str) -> Option<DateTime<Utc>> {
        self.next_scan_times.get(identifier).copied()
    }

    /// Get time until next scan for a domain
    pub fn time_until_next_scan(&self, identifier: &str) -> Option<Duration> {
        self.next_scan_time(identifier)
            .map(|next| next - Utc::now())
    }

    /// Get all scheduled scan times
    pub fn all_scheduled(&self) -> &HashMap<String, DateTime<Utc>> {
        &self.next_scan_times
    }

    /// Clear schedule for a domain
    pub fn clear_schedule(&mut self, identifier: &str) {
        self.next_scan_times.remove(identifier);
    }

    /// Clear all schedules
    pub fn clear_all(&mut self) {
        self.next_scan_times.clear();
    }

    /// Get count of scheduled domains
    pub fn scheduled_count(&self) -> usize {
        self.next_scan_times.len()
    }

    /// Reschedule a domain for immediate scan
    pub fn schedule_immediate(&mut self, identifier: &str) {
        self.next_scan_times
            .insert(identifier.to_string(), Utc::now());
    }

    /// Get domains scheduled in the next N seconds
    pub fn domains_due_within(&self, seconds: i64) -> Vec<String> {
        let threshold = Utc::now() + Duration::seconds(seconds);

        self.next_scan_times
            .iter()
            .filter(|&(_, time)| time <= &threshold)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

impl Default for SchedulingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::types::AlertThresholds;

    fn create_test_domain(hostname: &str, interval_seconds: u64) -> MonitoredDomain {
        MonitoredDomain {
            hostname: hostname.to_string(),
            port: 443,
            enabled: true,
            interval_seconds,
            alert_thresholds: AlertThresholds::default(),
            last_scan: None,
            last_certificate: None,
        }
    }

    #[test]
    fn test_new_scheduler() {
        let scheduler = SchedulingEngine::new();
        assert_eq!(scheduler.jitter_percent, 10);
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_custom_jitter() {
        let scheduler = SchedulingEngine::new().with_jitter(20);
        assert_eq!(scheduler.jitter_percent, 20);
    }

    #[test]
    fn test_jitter_cap() {
        let scheduler = SchedulingEngine::new().with_jitter(100);
        assert_eq!(scheduler.jitter_percent, 50); // Should be capped at 50%
    }

    #[test]
    fn test_first_scan_immediate() {
        let mut scheduler = SchedulingEngine::new();
        let domains = vec![create_test_domain("example.com", 3600)];

        let due_domains = scheduler.get_domains_to_scan(&domains);

        // First scan should be immediate
        assert_eq!(due_domains.len(), 1);
        assert_eq!(due_domains[0].hostname, "example.com");

        // Should have scheduled next scan
        assert_eq!(scheduler.scheduled_count(), 1);
    }

    #[test]
    fn test_schedule_next_scan() {
        let mut scheduler = SchedulingEngine::new();

        scheduler.schedule_next_scan("example.com:443", 3600);

        assert_eq!(scheduler.scheduled_count(), 1);
        assert!(scheduler.next_scan_time("example.com:443").is_some());
    }

    #[test]
    fn test_time_until_next_scan() {
        let mut scheduler = SchedulingEngine::new();

        scheduler.schedule_next_scan("example.com:443", 3600);

        let time_until = scheduler.time_until_next_scan("example.com:443");
        assert!(time_until.is_some());

        let duration = time_until.unwrap();
        // Should be around 3600 seconds (±10% jitter)
        assert!(duration.num_seconds() > 3200);
        assert!(duration.num_seconds() < 4000);
    }

    #[test]
    fn test_clear_schedule() {
        let mut scheduler = SchedulingEngine::new();

        scheduler.schedule_next_scan("example.com:443", 3600);
        assert_eq!(scheduler.scheduled_count(), 1);

        scheduler.clear_schedule("example.com:443");
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_clear_all() {
        let mut scheduler = SchedulingEngine::new();

        scheduler.schedule_next_scan("example.com:443", 3600);
        scheduler.schedule_next_scan("test.com:443", 1800);
        assert_eq!(scheduler.scheduled_count(), 2);

        scheduler.clear_all();
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_schedule_immediate() {
        let mut scheduler = SchedulingEngine::new();

        scheduler.schedule_immediate("example.com:443");

        let next_scan = scheduler.next_scan_time("example.com:443").unwrap();
        let now = Utc::now();

        // Should be scheduled for now (within 1 second tolerance)
        assert!((next_scan - now).num_seconds().abs() < 1);
    }

    #[test]
    fn test_domains_due_within() {
        let mut scheduler = SchedulingEngine::new();

        // Schedule one domain for immediate scan
        scheduler.schedule_immediate("immediate.com:443");

        // Schedule one domain far in the future
        scheduler.schedule_next_scan("future.com:443", 36000);

        let due_soon = scheduler.domains_due_within(60);

        // Only the immediate domain should be due within 60 seconds
        assert_eq!(due_soon.len(), 1);
        assert!(due_soon.contains(&"immediate.com:443".to_string()));
    }

    #[test]
    fn test_jitter_variation() {
        let scheduler = SchedulingEngine::new();

        let base_duration = Duration::seconds(3600);

        // Test multiple jitter applications - they should vary
        let mut results = std::collections::HashSet::new();
        for _ in 0..10 {
            let jittered = scheduler.add_jitter(base_duration);
            results.insert(jittered.num_seconds());
        }

        // Should have some variation (at least 2 different values in 10 attempts)
        assert!(results.len() >= 2);

        // All values should be within ±10% of base (3600 ± 360)
        for &seconds in &results {
            assert!(seconds >= 3240);
            assert!(seconds <= 3960);
        }
    }

    #[test]
    fn test_multiple_domains_scheduling() {
        let mut scheduler = SchedulingEngine::new();

        let domains = vec![
            create_test_domain("example1.com", 1800),
            create_test_domain("example2.com", 3600),
            create_test_domain("example3.com", 7200),
        ];

        // First scan - all should be due
        let due = scheduler.get_domains_to_scan(&domains);
        assert_eq!(due.len(), 3);

        // All should now be scheduled
        assert_eq!(scheduler.scheduled_count(), 3);

        // Immediately after, none should be due
        let due_again = scheduler.get_domains_to_scan(&domains);
        assert_eq!(due_again.len(), 0);
    }
}
