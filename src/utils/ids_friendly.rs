// IDS-friendly mode - Slower scanning to avoid triggering IDS/IPS
// Implements delays, rate limiting, and randomization

use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;

/// IDS-friendly configuration
#[derive(Debug, Clone)]
pub struct IdsFriendlyConfig {
    /// Minimum delay between requests (milliseconds)
    pub min_delay_ms: u64,
    /// Maximum delay between requests (milliseconds)
    pub max_delay_ms: u64,
    /// Use randomized delays
    pub randomize: bool,
    /// Maximum requests per minute
    pub max_requests_per_minute: usize,
}

impl Default for IdsFriendlyConfig {
    fn default() -> Self {
        Self {
            min_delay_ms: 1000, // 1 second minimum
            max_delay_ms: 3000, // 3 seconds maximum
            randomize: true,
            max_requests_per_minute: 20,
        }
    }
}

impl IdsFriendlyConfig {
    /// Create a new IDS-friendly configuration
    pub fn new(min_delay_ms: u64, max_delay_ms: u64) -> Self {
        Self {
            min_delay_ms,
            max_delay_ms,
            randomize: true,
            max_requests_per_minute: 20,
        }
    }

    /// Conservative preset (very slow, minimal IDS risk)
    pub fn conservative() -> Self {
        Self {
            min_delay_ms: 3000,  // 3 seconds
            max_delay_ms: 10000, // 10 seconds
            randomize: true,
            max_requests_per_minute: 6,
        }
    }

    /// Moderate preset (balanced speed/stealth)
    pub fn moderate() -> Self {
        Self {
            min_delay_ms: 500,  // 0.5 seconds
            max_delay_ms: 2000, // 2 seconds
            randomize: true,
            max_requests_per_minute: 30,
        }
    }

    /// Aggressive preset (faster, higher IDS risk)
    pub fn aggressive() -> Self {
        Self {
            min_delay_ms: 100, // 0.1 seconds
            max_delay_ms: 500, // 0.5 seconds
            randomize: true,
            max_requests_per_minute: 60,
        }
    }
}

/// IDS-friendly rate limiter
pub struct IdsFriendlyLimiter {
    config: IdsFriendlyConfig,
    request_count: usize,
    last_reset: std::time::Instant,
}

impl IdsFriendlyLimiter {
    /// Create a new IDS-friendly rate limiter
    pub fn new(config: IdsFriendlyConfig) -> Self {
        Self {
            config,
            request_count: 0,
            last_reset: std::time::Instant::now(),
        }
    }

    /// Wait before making next request
    pub async fn wait(&mut self) {
        // Check if we need to reset the counter
        if self.last_reset.elapsed() >= Duration::from_secs(60) {
            self.request_count = 0;
            self.last_reset = std::time::Instant::now();
        }

        // Check if we've exceeded the rate limit
        if self.request_count >= self.config.max_requests_per_minute {
            // Wait until the minute is up
            let elapsed = self.last_reset.elapsed();
            if elapsed < Duration::from_secs(60) {
                let wait_time = Duration::from_secs(60) - elapsed;
                sleep(wait_time).await;
            }
            self.request_count = 0;
            self.last_reset = std::time::Instant::now();
        }

        // Apply delay
        let delay_ms = if self.config.randomize {
            let mut rng = rand::thread_rng();
            rng.gen_range(self.config.min_delay_ms..=self.config.max_delay_ms)
        } else {
            self.config.min_delay_ms
        };

        sleep(Duration::from_millis(delay_ms)).await;

        self.request_count += 1;
    }

    /// Get remaining requests in current minute
    pub fn remaining_requests(&self) -> usize {
        self.config
            .max_requests_per_minute
            .saturating_sub(self.request_count)
    }

    /// Check if rate limit would be exceeded
    pub fn would_exceed_limit(&self) -> bool {
        self.request_count >= self.config.max_requests_per_minute
            && self.last_reset.elapsed() < Duration::from_secs(60)
    }
}

/// Apply randomized delay (jitter)
pub async fn random_delay(min_ms: u64, max_ms: u64) {
    let mut rng = rand::thread_rng();
    let delay_ms = rng.gen_range(min_ms..=max_ms);
    sleep(Duration::from_millis(delay_ms)).await;
}

/// Apply fixed delay
pub async fn fixed_delay(ms: u64) {
    sleep(Duration::from_millis(ms)).await;
}

/// Randomize order of items (to avoid predictable scanning patterns)
pub fn randomize_order<T>(items: &mut [T]) {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    items.shuffle(&mut rng);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_presets() {
        let conservative = IdsFriendlyConfig::conservative();
        assert!(conservative.min_delay_ms >= 3000);

        let moderate = IdsFriendlyConfig::moderate();
        assert!(moderate.min_delay_ms >= 500);

        let aggressive = IdsFriendlyConfig::aggressive();
        assert!(aggressive.min_delay_ms >= 100);
    }

    #[test]
    fn test_limiter_tracking() {
        let config = IdsFriendlyConfig::default();
        let limiter = IdsFriendlyLimiter::new(config);
        assert_eq!(limiter.request_count, 0);
        assert_eq!(limiter.remaining_requests(), 20);
    }

    #[test]
    fn test_randomize_order() {
        let mut items = vec![1, 2, 3, 4, 5];
        let original = items.clone();
        randomize_order(&mut items);
        // Items should still contain same elements
        assert_eq!(items.len(), original.len());
        for item in &original {
            assert!(items.contains(item));
        }
    }
}
