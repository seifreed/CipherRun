/// Rate Limiter - Configurable delay between connections
///
/// This module provides rate limiting functionality to add configurable delays
/// between network connections. This is useful for:
/// - Avoiding detection by IDS/IPS systems
/// - Reducing load on target systems
/// - Respecting rate limits of target services
/// - Preventing connection throttling or blocking
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Rate limiter for controlling connection timing
#[derive(Clone)]
pub struct RateLimiter {
    /// Minimum delay between requests
    delay: Duration,
    /// Last request timestamp
    last_request: Arc<Mutex<Option<Instant>>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified delay
    ///
    /// # Arguments
    /// * `delay` - The minimum duration between requests
    ///
    /// # Returns
    /// A new RateLimiter instance
    ///
    /// # Examples
    /// ```ignore
    /// let limiter = RateLimiter::new(Duration::from_millis(500));
    /// ```
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            last_request: Arc::new(Mutex::new(None)),
        }
    }

    /// Wait if necessary to maintain the rate limit
    ///
    /// This function will sleep if the time since the last request is less
    /// than the configured delay. After sleeping (or if no sleep is needed),
    /// it updates the last request timestamp.
    ///
    /// # Examples
    /// ```ignore
    /// let limiter = RateLimiter::new(Duration::from_secs(1));
    ///
    /// // First request: no wait
    /// limiter.wait().await;
    ///
    /// // Second request: will wait ~1 second
    /// limiter.wait().await;
    /// ```
    pub async fn wait(&self) {
        let mut last = self.last_request.lock().await;

        if let Some(last_time) = *last {
            let elapsed = last_time.elapsed();

            if elapsed < self.delay {
                let sleep_duration = self.delay - elapsed;
                tokio::time::sleep(sleep_duration).await;
            }
        }

        *last = Some(Instant::now());
    }

    /// Get the configured delay duration
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Reset the last request timestamp (useful for testing)
    pub async fn reset(&self) {
        let mut last = self.last_request.lock().await;
        *last = None;
    }

    /// Get the time until the next request can be made
    ///
    /// Returns the duration to wait before the next request is allowed.
    /// If no request has been made yet, returns Duration::ZERO.
    ///
    /// # Examples
    /// ```ignore
    /// let limiter = RateLimiter::new(Duration::from_secs(1));
    /// limiter.wait().await;
    ///
    /// let wait_time = limiter.time_until_next().await;
    /// // wait_time will be approximately 1 second
    /// ```
    pub async fn time_until_next(&self) -> Duration {
        let last = self.last_request.lock().await;

        match *last {
            Some(last_time) => {
                let elapsed = last_time.elapsed();
                if elapsed >= self.delay {
                    Duration::ZERO
                } else {
                    self.delay - elapsed
                }
            }
            None => Duration::ZERO,
        }
    }
}

/// Parse a delay string into a Duration
///
/// Supports the following formats:
/// - Milliseconds: "500" or "500ms"
/// - Seconds: "2s" or "2"
/// - Combinations: "1.5s"
///
/// # Arguments
/// * `s` - The delay string to parse
///
/// # Returns
/// A Result containing the parsed Duration or an error
///
/// # Examples
/// ```ignore
/// assert_eq!(parse_delay("500ms")?, Duration::from_millis(500));
/// assert_eq!(parse_delay("2s")?, Duration::from_secs(2));
/// assert_eq!(parse_delay("1.5s")?, Duration::from_millis(1500));
/// ```
pub fn parse_delay(s: &str) -> Result<Duration> {
    let s = s.trim();

    // Check for milliseconds suffix
    if let Some(value_str) = s.strip_suffix("ms") {
        let ms: u64 = value_str.trim().parse()?;
        return Ok(Duration::from_millis(ms));
    }

    // Check for seconds suffix
    if let Some(value_str) = s.strip_suffix('s') {
        // Support floating point seconds
        let seconds: f64 = value_str.trim().parse()?;
        let millis = (seconds * 1000.0) as u64;
        return Ok(Duration::from_millis(millis));
    }

    // Default to milliseconds if no suffix
    let ms: u64 = s.parse()?;
    Ok(Duration::from_millis(ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_no_delay_on_first_request() {
        let limiter = RateLimiter::new(Duration::from_millis(100));
        let start = Instant::now();
        limiter.wait().await;
        let elapsed = start.elapsed();

        // First request should be immediate
        assert!(elapsed.as_millis() < 50);
    }

    #[tokio::test]
    async fn test_delay_on_second_request() {
        let limiter = RateLimiter::new(Duration::from_millis(100));

        let start = Instant::now();
        limiter.wait().await; // First request
        limiter.wait().await; // Second request

        let elapsed = start.elapsed();

        // Second request should be delayed by ~100ms
        assert!(elapsed.as_millis() >= 95 && elapsed.as_millis() < 200);
    }

    #[tokio::test]
    async fn test_reset() {
        let limiter = RateLimiter::new(Duration::from_millis(100));

        limiter.wait().await;
        limiter.reset().await;

        let start = Instant::now();
        limiter.wait().await; // Should not wait since we reset
        let elapsed = start.elapsed();

        assert!(elapsed.as_millis() < 50);
    }

    #[tokio::test]
    async fn test_time_until_next() {
        let limiter = RateLimiter::new(Duration::from_millis(100));

        // Before first request
        assert_eq!(limiter.time_until_next().await, Duration::ZERO);

        limiter.wait().await;

        // Immediately after request
        let wait_time = limiter.time_until_next().await;
        assert!(wait_time.as_millis() > 50 && wait_time.as_millis() <= 100);
    }

    #[test]
    fn test_parse_delay_milliseconds() {
        assert_eq!(parse_delay("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_delay("1000ms").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_delay("0ms").unwrap(), Duration::ZERO);
    }

    #[test]
    fn test_parse_delay_seconds() {
        assert_eq!(parse_delay("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_delay("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_delay("0.5s").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_delay("1.5s").unwrap(), Duration::from_millis(1500));
    }

    #[test]
    fn test_parse_delay_plain_number() {
        // Plain numbers default to milliseconds
        assert_eq!(parse_delay("500").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_delay("1000").unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn test_parse_delay_with_whitespace() {
        assert_eq!(parse_delay("  500ms  ").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_delay("  2s  ").unwrap(), Duration::from_secs(2));
    }

    #[test]
    fn test_parse_delay_invalid() {
        assert!(parse_delay("invalid").is_err());
        assert!(parse_delay("abc ms").is_err());
        assert!(parse_delay("").is_err());
    }
}
