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
    /// Earliest instant at which the next request is allowed to start.
    /// Storing the *projected* next slot (instead of the last-request
    /// timestamp) lets concurrent waiters each reserve their own slot while
    /// holding the lock, spreading them out by `delay` instead of letting them
    /// all compute the same `sleep_duration` from the same observed `last`.
    next_allowed: Arc<Mutex<Option<Instant>>>,
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
            next_allowed: Arc::new(Mutex::new(None)),
        }
    }

    /// Wait if necessary to maintain the rate limit
    ///
    /// This function will sleep if the time since the last request is less
    /// than the configured delay. After sleeping (or if no sleep is needed),
    /// it updates the last request timestamp.
    ///
    /// # Concurrency Behavior
    ///
    /// This implementation uses a mutex-protected timestamp for rate limiting.
    /// Under high concurrency:
    /// - Multiple requests may acquire the lock simultaneously during the sleep phase
    /// - Each request calculates its own sleep duration based on the last timestamp
    /// - This can result in slightly lower effective rates under contention
    ///
    /// This is acceptable for the security scanning use case where:
    /// - Precise rate limiting is not critical
    /// - Occasional bursts slightly above the rate are harmless
    /// - Avoiding complex synchronization overhead is preferred
    ///
    /// For applications requiring strict rate limits under high concurrency,
    /// consider using a token bucket or sliding window algorithm.
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
        // I4 fix: reserve the slot *before* releasing the lock and sleeping.
        // Previous implementation released the lock without updating, so N
        // concurrent waiters all read the same `last_request`, all computed
        // the same `sleep_duration`, and all woke simultaneously — producing
        // a burst of N requests at the end of each delay window rather than
        // one-per-window spacing.
        let sleep_until = {
            let mut next = self.next_allowed.lock().await;
            let now = Instant::now();
            let target = match *next {
                Some(t) if t > now => t,
                _ => now,
            };
            // The request that holds this lock will fire at `target`; the next
            // waiter must wait until `target + self.delay`.
            *next = Some(target + self.delay);
            target
        };

        if sleep_until > Instant::now() {
            tokio::time::sleep_until(tokio::time::Instant::from_std(sleep_until)).await;
        }
    }

    /// Get the configured delay duration
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Reset the limiter's slot reservation (useful for testing)
    pub async fn reset(&self) {
        let mut next = self.next_allowed.lock().await;
        *next = None;
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
        let next = self.next_allowed.lock().await;
        let now = Instant::now();
        match *next {
            Some(t) if t > now => t - now,
            _ => Duration::ZERO,
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
/// Negative values are not supported.
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

    // Reject negative values
    if s.starts_with('-') {
        anyhow::bail!("Negative delays are not supported: {}", s);
    }

    // Check for milliseconds suffix
    if let Some(value_str) = s.strip_suffix("ms") {
        let ms: u64 = value_str.trim().parse()?;
        return Ok(Duration::from_millis(ms));
    }

    // Check for seconds suffix
    if let Some(value_str) = s.strip_suffix('s') {
        // Support floating point seconds
        let seconds: f64 = value_str.trim().parse()?;
        if !seconds.is_finite() || seconds < 0.0 {
            anyhow::bail!("Invalid delay value: {}", s);
        }
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

    #[tokio::test]
    async fn test_time_until_next_zero_after_elapsed() {
        let limiter = RateLimiter::new(Duration::from_millis(50));
        // With the new semantics, set `next_allowed` to a past instant so
        // `time_until_next` reports zero regardless of monotonic clock.
        {
            let mut next = limiter.next_allowed.lock().await;
            *next = Some(Instant::now() - Duration::from_millis(200));
        }

        let wait_time = limiter.time_until_next().await;
        assert_eq!(wait_time, Duration::ZERO);
    }

    /// I4 regression: concurrent waiters must be spread by ~`delay` each,
    /// not all fire simultaneously after a single sleep window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_rate_limiter_spreads_concurrent_waiters() {
        let limiter = RateLimiter::new(Duration::from_millis(100));
        let start = Instant::now();
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let l = limiter.clone();
                tokio::spawn(async move {
                    l.wait().await;
                    Instant::now()
                })
            })
            .collect();

        let mut times: Vec<Instant> = Vec::with_capacity(5);
        for h in handles {
            times.push(h.await.expect("task completed"));
        }
        times.sort();

        // Each successive waiter should fire at least ~90 ms after the prior
        // (some scheduling slack). The old race allowed all five to fire
        // within a few ms of each other.
        for w in times.windows(2) {
            let gap = w[1] - w[0];
            assert!(
                gap >= Duration::from_millis(80),
                "concurrent waiters must be spread by ~delay; gap was {:?}",
                gap
            );
        }
        // And total span should be roughly 4 * delay.
        let total = times.last().unwrap().duration_since(start);
        assert!(
            total >= Duration::from_millis(350),
            "5 waiters over 100ms delay should take ≥400ms total; got {:?}",
            total
        );
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
    fn test_parse_delay_fractional_seconds() {
        assert_eq!(parse_delay("1.25s").unwrap(), Duration::from_millis(1250));
    }

    #[test]
    fn test_rate_limiter_delay_accessor() {
        let limiter = RateLimiter::new(Duration::from_millis(250));
        assert_eq!(limiter.delay(), Duration::from_millis(250));
    }

    #[test]
    fn test_parse_delay_with_whitespace() {
        assert_eq!(
            parse_delay("  500ms  ").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(parse_delay("  2s  ").unwrap(), Duration::from_secs(2));
    }

    #[test]
    fn test_parse_delay_invalid() {
        assert!(parse_delay("invalid").is_err());
        assert!(parse_delay("abc ms").is_err());
        assert!(parse_delay("").is_err());
    }

    #[test]
    fn test_parse_delay_rejects_non_finite_seconds() {
        assert!(parse_delay("NaNs").is_err());
        assert!(parse_delay("infs").is_err());
    }

    #[test]
    fn test_parse_delay_negative_rejected() {
        assert!(parse_delay("-1").is_err());
        assert!(parse_delay("-2s").is_err());
    }

    #[tokio::test]
    async fn test_time_until_next_zero_after_reset() {
        let limiter = RateLimiter::new(Duration::from_millis(50));
        limiter.wait().await;
        limiter.reset().await;
        assert_eq!(limiter.time_until_next().await, Duration::ZERO);
    }
}
