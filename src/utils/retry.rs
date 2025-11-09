// Retry utilities - Exponential backoff and retry logic for network operations
//
// This module provides configurable retry logic with exponential backoff for handling
// transient network failures. It distinguishes between retriable errors (e.g., connection
// timeouts, connection resets) and non-retriable errors (e.g., connection refused, DNS failures).

use std::future::Future;
use std::time::Duration;
use anyhow::Result;

/// Configuration for retry behavior with exponential backoff.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use cipherrun::utils::retry::RetryConfig;
///
/// let config = RetryConfig {
///     max_retries: 3,
///     initial_backoff: Duration::from_millis(100),
///     max_backoff: Duration::from_secs(5),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts before giving up.
    /// Default: 3
    pub max_retries: usize,

    /// Initial backoff duration for the first retry.
    /// Subsequent retries will use exponential backoff (doubled each time).
    /// Default: 100ms
    pub initial_backoff: Duration,

    /// Maximum backoff duration to prevent excessive delays.
    /// Default: 5 seconds
    pub max_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration with custom values.
    pub fn new(max_retries: usize, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            max_retries,
            initial_backoff,
            max_backoff,
        }
    }

    /// Create a configuration with no retries (fail immediately on error).
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
        }
    }

    /// Create a configuration optimized for fast scans with minimal retries.
    pub fn fast() -> Self {
        Self {
            max_retries: 1,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(500),
        }
    }

    /// Create a configuration optimized for unstable networks with more retries.
    pub fn robust() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
        }
    }
}

/// Retry an async operation with exponential backoff.
///
/// This function will retry the given operation up to `max_retries` times,
/// using exponential backoff between attempts. It distinguishes between
/// retriable and non-retriable errors to avoid unnecessary retries.
///
/// # Retriable vs Non-Retriable Errors
///
/// **Retriable errors** (transient failures that may succeed on retry):
/// - Connection timeout (network congestion, temporary unavailability)
/// - Connection reset by peer (server temporarily overwhelmed)
/// - Connection aborted (interrupted by network issues)
/// - Broken pipe (connection lost mid-operation)
/// - Network unreachable (temporary routing issues)
/// - Host unreachable (temporary network partition)
///
/// **Non-retriable errors** (permanent failures that won't succeed on retry):
/// - Connection refused (service not running or firewall blocking)
/// - DNS resolution failure (hostname doesn't exist)
/// - Invalid DNS name (malformed hostname)
/// - Invalid input (programming error)
/// - Address not available (invalid bind address)
/// - Permission denied (firewall or OS policy)
///
/// # Arguments
///
/// * `config` - Retry configuration controlling behavior
/// * `operation` - Async closure that returns a Result<T>
///
/// # Returns
///
/// Returns the result of the operation if it succeeds within the retry limit,
/// or the last error if all retries are exhausted.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use cipherrun::utils::retry::{RetryConfig, retry_with_backoff};
/// use tokio::net::TcpStream;
/// use std::net::SocketAddr;
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = RetryConfig::default();
/// let addr: SocketAddr = "192.0.2.1:443".parse()?;
///
/// let stream = retry_with_backoff(&config, || async {
///     TcpStream::connect(addr).await.map_err(Into::into)
/// }).await?;
/// # Ok(())
/// # }
/// ```
pub async fn retry_with_backoff<F, Fut, T>(
    config: &RetryConfig,
    operation: F,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut retries = 0;
    let mut backoff = config.initial_backoff;

    loop {
        match operation().await {
            Ok(result) => {
                if retries > 0 {
                    tracing::debug!(
                        "Operation succeeded after {} retry(ies)",
                        retries
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                // Check if we should retry this error
                if !is_retriable(&e) {
                    tracing::debug!(
                        "Non-retriable error encountered: {}",
                        e
                    );
                    return Err(e);
                }

                // Check if we've exhausted retries
                if retries >= config.max_retries {
                    tracing::debug!(
                        "Max retries ({}) exhausted, giving up: {}",
                        config.max_retries,
                        e
                    );
                    return Err(e);
                }

                // Log retry attempt
                retries += 1;
                tracing::warn!(
                    "Attempt {}/{} failed: {}, retrying in {:?}",
                    retries,
                    config.max_retries,
                    e,
                    backoff
                );

                // Wait with current backoff
                tokio::time::sleep(backoff).await;

                // Calculate next backoff (exponential with cap)
                backoff = std::cmp::min(backoff * 2, config.max_backoff);
            }
        }
    }
}

/// Determine if an error should be retried.
///
/// This function analyzes the error to determine if it represents a transient
/// failure that might succeed on retry, or a permanent failure that will not.
///
/// # Error Classification Strategy
///
/// 1. **IO Errors**: Analyzed by error kind
///    - Retriable: TimedOut, ConnectionReset, ConnectionAborted, BrokenPipe,
///      NetworkUnreachable, HostUnreachable
///    - Non-retriable: ConnectionRefused, NotFound, PermissionDenied, AddrNotAvailable
///
/// 2. **String-based analysis**: For errors without structured types, we examine
///    the error message for known patterns:
///    - Timeout indicators: "timeout", "timed out", "deadline"
///    - Reset indicators: "reset", "connection reset"
///    - Refusal indicators: "refused", "connection refused"
///    - DNS failures: "failed to lookup", "name or service not known"
///
/// # Arguments
///
/// * `error` - The error to analyze
///
/// # Returns
///
/// `true` if the error is retriable, `false` otherwise
fn is_retriable(error: &anyhow::Error) -> bool {
    // Check if it's an IO error first (most common case)
    if let Some(io_err) = error.downcast_ref::<std::io::Error>() {
        return is_io_error_retriable(io_err);
    }

    // For other error types, analyze the error message
    let error_msg = error.to_string().to_lowercase();

    // Retriable patterns (transient failures)
    let retriable_patterns = [
        "timeout",
        "timed out",
        "deadline",
        "connection reset",
        "reset by peer",
        "connection aborted",
        "broken pipe",
        "network unreachable",
        "host unreachable",
        "temporary failure",
        "try again",
    ];

    // Non-retriable patterns (permanent failures)
    let non_retriable_patterns = [
        "connection refused",
        "refused",
        "failed to lookup",
        "name or service not known",
        "invalid dns name",
        "no such host",
        "permission denied",
        "address not available",
    ];

    // Check non-retriable patterns first (more specific)
    for pattern in &non_retriable_patterns {
        if error_msg.contains(pattern) {
            return false;
        }
    }

    // Check retriable patterns
    for pattern in &retriable_patterns {
        if error_msg.contains(pattern) {
            return true;
        }
    }

    // Default to non-retriable for unknown errors
    // This is a conservative choice to avoid excessive retries
    false
}

/// Analyze IO error to determine if it's retriable.
///
/// # Arguments
///
/// * `error` - The IO error to analyze
///
/// # Returns
///
/// `true` if the IO error is retriable, `false` otherwise
fn is_io_error_retriable(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    match error.kind() {
        // Retriable: Transient network issues
        ErrorKind::TimedOut => true,
        ErrorKind::ConnectionReset => true,
        ErrorKind::ConnectionAborted => true,
        ErrorKind::BrokenPipe => true,
        ErrorKind::Interrupted => true,
        ErrorKind::WouldBlock => true,

        // Non-retriable: Service unavailable or configuration issues
        ErrorKind::ConnectionRefused => false,
        ErrorKind::NotFound => false,
        ErrorKind::PermissionDenied => false,
        ErrorKind::AddrNotAvailable => false,
        ErrorKind::AddrInUse => false,
        ErrorKind::InvalidInput => false,
        ErrorKind::InvalidData => false,

        // Other errors: analyze message for network-related issues
        _ => {
            let msg = error.to_string().to_lowercase();
            // Check for network unreachable patterns
            msg.contains("network unreachable")
                || msg.contains("host unreachable")
                || msg.contains("no route to host")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
        assert_eq!(config.max_backoff, Duration::from_secs(5));
    }

    #[test]
    fn test_retry_config_presets() {
        let no_retry = RetryConfig::no_retry();
        assert_eq!(no_retry.max_retries, 0);

        let fast = RetryConfig::fast();
        assert_eq!(fast.max_retries, 1);
        assert_eq!(fast.initial_backoff, Duration::from_millis(50));

        let robust = RetryConfig::robust();
        assert_eq!(robust.max_retries, 5);
        assert_eq!(robust.initial_backoff, Duration::from_millis(200));
    }

    #[test]
    fn test_is_io_error_retriable() {
        // Retriable errors
        assert!(is_io_error_retriable(&Error::new(
            ErrorKind::TimedOut,
            "timeout"
        )));
        assert!(is_io_error_retriable(&Error::new(
            ErrorKind::ConnectionReset,
            "reset"
        )));
        assert!(is_io_error_retriable(&Error::new(
            ErrorKind::ConnectionAborted,
            "aborted"
        )));
        assert!(is_io_error_retriable(&Error::new(
            ErrorKind::BrokenPipe,
            "broken"
        )));

        // Non-retriable errors
        assert!(!is_io_error_retriable(&Error::new(
            ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(!is_io_error_retriable(&Error::new(
            ErrorKind::NotFound,
            "not found"
        )));
        assert!(!is_io_error_retriable(&Error::new(
            ErrorKind::PermissionDenied,
            "denied"
        )));
        assert!(!is_io_error_retriable(&Error::new(
            ErrorKind::InvalidInput,
            "invalid"
        )));
    }

    #[test]
    fn test_is_retriable_by_message() {
        // Retriable based on message
        let timeout_err = anyhow::anyhow!("Connection timed out");
        assert!(is_retriable(&timeout_err));

        let reset_err = anyhow::anyhow!("Connection reset by peer");
        assert!(is_retriable(&reset_err));

        // Non-retriable based on message
        let refused_err = anyhow::anyhow!("Connection refused");
        assert!(!is_retriable(&refused_err));

        let dns_err = anyhow::anyhow!("Failed to lookup host");
        assert!(!is_retriable(&dns_err));

        // Unknown error - default to non-retriable
        let unknown_err = anyhow::anyhow!("Unknown error");
        assert!(!is_retriable(&unknown_err));
    }

    #[tokio::test]
    async fn test_retry_success_on_first_attempt() {
        let config = RetryConfig::default();
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);

        let result = retry_with_backoff(&config, || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Ok::<_, anyhow::Error>(42)
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_success_after_retries() {
        let config = RetryConfig::default();
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);

        let result = retry_with_backoff(&config, || async {
            let current = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if current < 3 {
                Err(anyhow::anyhow!("Connection timed out"))
            } else {
                Ok::<_, anyhow::Error>(42)
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_exhaustion() {
        let config = RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);

        let result = retry_with_backoff(&config, || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::anyhow!("Connection timed out"))
        })
        .await;

        assert!(result.is_err());
        // Original attempt + 2 retries = 3 total
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_no_retry_on_non_retriable() {
        let config = RetryConfig::default();
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);

        let result = retry_with_backoff(&config, || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::anyhow!("Connection refused"))
        })
        .await;

        assert!(result.is_err());
        // Should fail immediately without retries
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
        };

        let start = std::time::Instant::now();
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);

        let _result = retry_with_backoff(&config, || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::anyhow!("timeout"))
        })
        .await;

        let elapsed = start.elapsed();

        // Should have waited approximately:
        // 10ms + 20ms + 40ms = 70ms total
        // But capped at 50ms for last retry: 10ms + 20ms + 50ms = 80ms
        // Allow some tolerance
        assert!(elapsed >= Duration::from_millis(70));
        assert!(elapsed < Duration::from_millis(150));
        assert_eq!(attempts.load(Ordering::SeqCst), 4); // 1 initial + 3 retries
    }
}
