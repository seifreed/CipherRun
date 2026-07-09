// Scheduling Engine - Manages scan intervals and timing

use crate::Result;
use crate::monitor::inventory::{
    MonitoredDomain, canonical_inventory_key, validate_monitor_interval_seconds,
};
use crate::security::validate_hostname;
use crate::utils::network::split_target_host_port;
use chrono::{DateTime, Duration, Utc};
use rand::RngExt;
use std::collections::HashMap;

/// Scheduling engine for managing domain scan intervals
pub struct SchedulingEngine {
    next_scan_times: HashMap<String, DateTime<Utc>>,
    in_progress: std::collections::HashSet<String>,
    jitter_percent: u8,
}

impl SchedulingEngine {
    /// Create new scheduling engine
    pub fn new() -> Self {
        Self {
            next_scan_times: HashMap::new(),
            in_progress: std::collections::HashSet::new(),
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
            // Skip domains that are already being scanned
            if self.in_progress.contains(&identifier) {
                continue;
            }

            let is_due = if let Some(next_scan) = self.next_scan_times.get(&identifier) {
                now >= *next_scan
            } else {
                // First scan - schedule immediately
                true
            };

            if is_due {
                due_domains.push(domain);
            }
        }

        due_domains
    }

    /// Mark a domain as currently being scanned to prevent concurrent scans
    pub fn mark_scan_in_progress(&mut self, domain: &MonitoredDomain) {
        self.in_progress.insert(domain.identifier());
    }

    /// Mark a scan as completed and schedule the next one
    pub fn mark_scan_completed(&mut self, domain: &MonitoredDomain) -> Result<()> {
        let identifier = domain.identifier();
        self.in_progress.remove(&identifier);
        self.schedule_next_scan_internal(&identifier, domain.interval_seconds)
    }

    /// Schedule next scan for a domain
    pub fn schedule_next_scan(&mut self, hostname: &str, interval_seconds: u64) -> Result<()> {
        self.schedule_next_scan_internal(hostname, interval_seconds)
    }

    /// Internal method to schedule next scan with jitter
    fn schedule_next_scan_internal(
        &mut self,
        identifier: &str,
        interval_seconds: u64,
    ) -> Result<()> {
        validate_monitor_interval_seconds(interval_seconds)?;
        let identifier = try_canonical_schedule_key(identifier)?;
        let seconds =
            i64::try_from(interval_seconds).map_err(|_| crate::TlsError::InvalidInput {
                message: "Monitored domain interval is too large".to_string(),
            })?;
        let interval =
            Duration::try_seconds(seconds).ok_or_else(|| crate::TlsError::InvalidInput {
                message: "Monitored domain interval is too large".to_string(),
            })?;
        let interval_with_jitter = self.add_jitter(interval);
        let next_scan = Self::checked_next_scan(Utc::now(), interval_with_jitter)?;

        self.next_scan_times.insert(identifier, next_scan);
        Ok(())
    }

    fn checked_next_scan(now: DateTime<Utc>, interval: Duration) -> Result<DateTime<Utc>> {
        now.checked_add_signed(interval)
            .ok_or_else(|| crate::TlsError::InvalidInput {
                message: "Monitored domain interval is too large".to_string(),
            })
    }

    /// Add jitter to duration to prevent thundering herd
    ///
    /// Adds random variation of ±jitter_percent to the duration
    fn add_jitter(&self, duration: Duration) -> Duration {
        let mut rng = rand::rng();

        // Calculate jitter range with overflow protection
        let seconds = duration.num_seconds();
        let mut jitter_range = (seconds.saturating_mul(self.jitter_percent as i64) + 50) / 100;
        // Guarantee at least 1 second of jitter to prevent a thundering herd even for short
        // intervals; a jitter_percent of 0 disables jitter entirely and is honored here.
        if self.jitter_percent > 0 && seconds > 0 {
            jitter_range = jitter_range.max(1);
        }

        // Random jitter between -jitter_range and +jitter_range
        let jitter = rng.random_range(-jitter_range..=jitter_range);

        // Use saturating arithmetic to prevent overflow
        let adjusted_seconds = seconds.saturating_add(jitter).max(0);

        Duration::seconds(adjusted_seconds)
    }

    /// Get next scan time for a domain
    pub fn next_scan_time(&self, identifier: &str) -> Option<DateTime<Utc>> {
        let identifier = try_canonical_schedule_key(identifier).ok()?;
        self.next_scan_times.get(&identifier).copied()
    }

    /// Get time until next scan for a domain
    pub fn time_until_next_scan(&self, identifier: &str) -> Option<Duration> {
        self.next_scan_time(identifier)
            .map(|next| next - Utc::now())
    }

    /// Clear schedule for a domain
    pub fn clear_schedule(&mut self, identifier: &str) {
        let Some(identifier) = try_canonical_schedule_key(identifier).ok() else {
            return;
        };
        self.next_scan_times.remove(&identifier);
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
        let Some(identifier) = try_canonical_schedule_key(identifier).ok() else {
            return;
        };
        self.next_scan_times.insert(identifier, Utc::now());
    }

    /// Get domains scheduled in the next N seconds
    pub fn domains_due_within(&self, seconds: i64) -> Vec<String> {
        let Some(duration) = Duration::try_seconds(seconds) else {
            return if seconds.is_negative() {
                Vec::new()
            } else {
                self.next_scan_times.keys().cloned().collect()
            };
        };
        let Some(threshold) = Utc::now().checked_add_signed(duration) else {
            return if seconds.is_negative() {
                Vec::new()
            } else {
                self.next_scan_times.keys().cloned().collect()
            };
        };

        self.next_scan_times
            .iter()
            .filter(|&(_, time)| time <= &threshold)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

fn try_canonical_schedule_key(identifier: &str) -> Result<String> {
    let (hostname, port) = split_target_host_port(identifier)?;
    validate_hostname(&hostname).map_err(|error| crate::TlsError::InvalidInput {
        message: error.to_string(),
    })?;
    Ok(canonical_inventory_key(&hostname, port.unwrap_or(443)))
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
    fn test_short_interval_keeps_minimum_jitter() {
        // A 1-second interval at 10% would round to 0 jitter, pinning every result to
        // exactly 1 second. The engine must apply at least ±1 second so short intervals
        // avoid a thundering herd, producing a spread across {0, 1, 2}.
        let scheduler = SchedulingEngine::new();
        let mut spread = false;
        for _ in 0..256 {
            let adjusted = scheduler.add_jitter(Duration::seconds(1)).num_seconds();
            assert!((0..=2).contains(&adjusted));
            if adjusted != 1 {
                spread = true;
            }
        }
        assert!(
            spread,
            "expected non-degenerate jitter range for a 1-second interval"
        );
    }

    #[test]
    fn test_disabled_jitter_leaves_interval_unchanged() {
        let scheduler = SchedulingEngine::new().with_jitter(0);
        let adjusted = scheduler.add_jitter(Duration::seconds(3600)).num_seconds();
        assert_eq!(adjusted, 3600);
    }

    #[test]
    fn test_first_scan_immediate() {
        let mut scheduler = SchedulingEngine::new();
        let domains = vec![create_test_domain("example.com", 3600)];

        let due_domains = scheduler.get_domains_to_scan(&domains);

        // First scan should be immediate
        assert_eq!(due_domains.len(), 1);
        assert_eq!(due_domains[0].hostname, "example.com");

        // Not yet scheduled — only scheduled after mark_scan_completed
        assert_eq!(scheduler.scheduled_count(), 0);

        // Simulate successful scan completion
        scheduler
            .mark_scan_completed(due_domains[0])
            .expect("valid interval should schedule");
        assert_eq!(scheduler.scheduled_count(), 1);
    }

    #[test]
    fn test_schedule_next_scan() {
        let mut scheduler = SchedulingEngine::new();

        scheduler
            .schedule_next_scan("example.com:443", 3600)
            .expect("valid interval should schedule");

        assert_eq!(scheduler.scheduled_count(), 1);
        assert!(scheduler.next_scan_time("example.com:443").is_some());
    }

    #[test]
    fn test_schedule_next_scan_rejects_invalid_identifier() {
        let mut scheduler = SchedulingEngine::new();

        let err = scheduler
            .schedule_next_scan("example.com:notaport", 3600)
            .expect_err("invalid target should not be scheduled");

        assert!(err.to_string().contains("Invalid port number"));
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_schedule_next_scan_normalizes_domain_identifier_case() {
        let mut scheduler = SchedulingEngine::new();
        let domains = vec![create_test_domain("example.com", 3600)];

        scheduler
            .schedule_next_scan("Example.COM:443", 3600)
            .expect("valid interval should schedule");

        assert_eq!(scheduler.scheduled_count(), 1);
        assert!(scheduler.next_scan_time("example.com:443").is_some());
        assert!(scheduler.get_domains_to_scan(&domains).is_empty());

        scheduler.clear_schedule("EXAMPLE.com:443");
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_schedule_next_scan_normalizes_rooted_fqdn_identifier() {
        let mut scheduler = SchedulingEngine::new();
        let domains = vec![create_test_domain("example.com", 3600)];

        scheduler
            .schedule_next_scan("Example.COM.:443", 3600)
            .expect("valid interval should schedule");

        assert_eq!(scheduler.scheduled_count(), 1);
        assert!(scheduler.next_scan_time("example.com:443").is_some());
        assert!(scheduler.get_domains_to_scan(&domains).is_empty());
    }

    #[test]
    fn test_time_until_next_scan() {
        let mut scheduler = SchedulingEngine::new();

        scheduler
            .schedule_next_scan("example.com:443", 3600)
            .expect("valid interval should schedule");

        let time_until = scheduler.time_until_next_scan("example.com:443");
        assert!(time_until.is_some());

        let duration = time_until.expect("test assertion should succeed");
        // Should be around 3600 seconds (±10% jitter)
        assert!(duration.num_seconds() > 3200);
        assert!(duration.num_seconds() < 4000);
    }

    #[test]
    fn test_clear_schedule() {
        let mut scheduler = SchedulingEngine::new();

        scheduler
            .schedule_next_scan("example.com:443", 3600)
            .expect("valid interval should schedule");
        assert_eq!(scheduler.scheduled_count(), 1);

        scheduler.clear_schedule("example.com:443");
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_clear_all() {
        let mut scheduler = SchedulingEngine::new();

        scheduler
            .schedule_next_scan("example.com:443", 3600)
            .expect("valid interval should schedule");
        scheduler
            .schedule_next_scan("test.com:443", 1800)
            .expect("valid interval should schedule");
        assert_eq!(scheduler.scheduled_count(), 2);

        scheduler.clear_all();
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_schedule_immediate() {
        let mut scheduler = SchedulingEngine::new();

        scheduler.schedule_immediate("example.com:443");

        let next_scan = scheduler
            .next_scan_time("example.com:443")
            .expect("test assertion should succeed");
        let now = Utc::now();

        // Should be scheduled for now (within 1 second tolerance)
        assert!((next_scan - now).num_seconds().abs() < 1);
    }

    #[test]
    fn test_invalid_identifier_does_not_create_schedule_entry() {
        let mut scheduler = SchedulingEngine::new();

        scheduler.schedule_immediate("example.com/path");
        assert_eq!(scheduler.scheduled_count(), 0);
        assert!(scheduler.next_scan_time("example.com/path").is_none());

        scheduler.clear_schedule("example.com/path");
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_domains_due_within() {
        let mut scheduler = SchedulingEngine::new();

        // Schedule one domain for immediate scan
        scheduler.schedule_immediate("immediate.com:443");

        // Schedule one domain far in the future
        scheduler
            .schedule_next_scan("future.com:443", 36000)
            .expect("valid interval should schedule");

        let due_soon = scheduler.domains_due_within(60);

        // Only the immediate domain should be due within 60 seconds
        assert_eq!(due_soon.len(), 1);
        assert!(due_soon.contains(&"immediate.com:443".to_string()));
    }

    #[test]
    fn test_domains_due_within_large_positive_window_includes_scheduled_domains() {
        let mut scheduler = SchedulingEngine::new();
        scheduler.schedule_immediate("immediate.com:443");
        scheduler
            .schedule_next_scan("future.com:443", 36000)
            .expect("valid interval should schedule");

        let mut due = scheduler.domains_due_within(i64::MAX);
        due.sort();

        assert_eq!(
            due,
            vec![
                "future.com:443".to_string(),
                "immediate.com:443".to_string()
            ]
        );
    }

    #[test]
    fn test_domains_due_within_large_negative_window_is_empty() {
        let mut scheduler = SchedulingEngine::new();
        scheduler.schedule_immediate("immediate.com:443");

        assert!(scheduler.domains_due_within(i64::MIN).is_empty());
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

        // Not yet scheduled — mark all as completed
        assert_eq!(scheduler.scheduled_count(), 0);
        for domain in &due {
            scheduler
                .mark_scan_completed(domain)
                .expect("valid interval should schedule");
        }
        assert_eq!(scheduler.scheduled_count(), 3);

        // Immediately after, none should be due
        let due_again = scheduler.get_domains_to_scan(&domains);
        assert_eq!(due_again.len(), 0);
    }

    #[test]
    fn test_time_until_next_scan_unknown() {
        let scheduler = SchedulingEngine::new();
        assert!(scheduler.time_until_next_scan("missing:443").is_none());
    }

    #[test]
    fn test_schedule_rejects_interval_too_large_for_chrono() {
        let mut scheduler = SchedulingEngine::new();
        let err = scheduler
            .schedule_next_scan("example.com:443", u64::MAX)
            .expect_err("oversized interval should fail");

        assert!(err.to_string().contains("interval"));
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_schedule_rejects_interval_beyond_datetime_range() {
        let mut scheduler = SchedulingEngine::new().with_jitter(0);
        let err = scheduler
            .schedule_next_scan("example.com:443", i64::MAX as u64)
            .expect_err("interval beyond DateTime range should fail");

        assert!(err.to_string().contains("interval"));
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_checked_next_scan_rejects_datetime_overflow() {
        let err =
            SchedulingEngine::checked_next_scan(DateTime::<Utc>::MAX_UTC, Duration::seconds(1))
                .expect_err("datetime overflow should fail");

        assert!(err.to_string().contains("interval"));
    }
}
