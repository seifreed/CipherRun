/// Tests for Feature 14: Rate Limiting / Connection Delay
///
/// This test file verifies the rate limiting functionality,
/// which adds configurable delays between connections.
#[cfg(test)]
mod rate_limiter_tests {
    use cipherrun::utils::rate_limiter::{RateLimiter, parse_delay};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn test_no_delay_on_first_request() {
        let limiter = RateLimiter::new(Duration::from_millis(100));
        let start = Instant::now();
        limiter.wait().await;
        let elapsed = start.elapsed();

        // First request should be immediate (less than 50ms)
        assert!(elapsed.as_millis() < 50);
    }

    #[tokio::test]
    async fn test_delay_on_second_request() {
        let limiter = RateLimiter::new(Duration::from_millis(100));

        let start = Instant::now();
        limiter.wait().await; // First request
        limiter.wait().await; // Second request - should be delayed
        let elapsed = start.elapsed();

        // Should take at least 100ms total
        assert!(elapsed.as_millis() >= 95);
    }

    #[tokio::test]
    async fn test_multiple_requests_respect_delay() {
        let limiter = RateLimiter::new(Duration::from_millis(50));

        let start = Instant::now();
        for _ in 0..3 {
            limiter.wait().await;
        }
        let elapsed = start.elapsed();

        // 3 requests with 50ms delay between them should take at least 100ms
        assert!(elapsed.as_millis() >= 95);
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
    fn test_parse_delay_floating_point() {
        assert_eq!(parse_delay("2.5s").unwrap(), Duration::from_millis(2500));
        assert_eq!(parse_delay("0.1s").unwrap(), Duration::from_millis(100));
    }

    #[test]
    fn test_limiter_delay_getter() {
        let limiter = RateLimiter::new(Duration::from_secs(1));
        assert_eq!(limiter.delay(), Duration::from_secs(1));
    }

    #[test]
    fn test_limiter_cloneable() {
        let limiter1 = RateLimiter::new(Duration::from_millis(100));
        let limiter2 = limiter1.clone();

        assert_eq!(limiter1.delay(), limiter2.delay());
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let limiter = std::sync::Arc::new(RateLimiter::new(Duration::from_millis(50)));

        let handles: Vec<_> = (0..3)
            .map(|_| {
                let limiter = limiter.clone();
                tokio::spawn(async move {
                    limiter.wait().await;
                })
            })
            .collect();

        let start = Instant::now();
        for handle in handles {
            handle.await.unwrap();
        }
        let elapsed = start.elapsed();

        // All requests should respect the rate limit
        assert!(elapsed.as_millis() >= 40);
    }

    #[test]
    fn test_parse_delay_edge_cases() {
        // Very small delays
        assert_eq!(parse_delay("1ms").unwrap(), Duration::from_millis(1));
        assert_eq!(parse_delay("0.1s").unwrap(), Duration::from_millis(100));

        // Large delays
        assert_eq!(parse_delay("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_delay("5000ms").unwrap(), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_zero_delay() {
        let limiter = RateLimiter::new(Duration::ZERO);

        let start = Instant::now();
        limiter.wait().await;
        limiter.wait().await;
        let elapsed = start.elapsed();

        // No delay means immediate execution
        assert!(elapsed.as_millis() < 50);
    }
}
