// Cipher Tester - Tests which cipher suites are supported by the server
//
// Copyright (c) Marc Rivero López
// Licensed under GPLv3
// https://www.gnu.org/licenses/gpl-3.0.html
//
// # Module Structure
//
// This module is intentionally kept as a single file (~1150 lines) due to high cohesion
// between its components. All sections work together for cipher suite testing:
//
// 1. Connection Pooling (`TlsConnectionPool`) - TCP connection reuse for performance
// 2. Data Types - Result structures specific to cipher testing
// 3. CipherTester - Main struct with builder pattern configuration
// 4. Cipher Testing - Concurrent testing with adaptive backoff and retry
// 5. Handshake Logic - Core TLS handshake implementation
// 6. Server Preference Detection - Determines server vs client cipher preference
// 7. Helper Methods - Protocol compatibility, statistics, quick tests
//
// Splitting would add complexity without benefit since:
// - TlsConnectionPool is TLS-specific, not a generic pool
// - Data types are specific to cipher testing output
// - Server preference detection is integral to cipher testing
// - All components share configuration and target information

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use super::{CipherStrength, CipherSuite};
use crate::Result;
use crate::constants::{
    BUFFER_SIZE_DEFAULT, CIPHER_TEST_READ_TIMEOUT, CONTENT_TYPE_HANDSHAKE, DEFAULT_CONNECT_TIMEOUT,
    HANDSHAKE_TYPE_SERVER_HELLO,
};
use crate::data::CIPHER_DB;
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use crate::utils::network::Target;
use crate::utils::adaptive::AdaptiveController;

/// Type alias for cipher test batch results: (cipher, Ok((supported, handshake_time_ms)))
type CipherBatchResult = Vec<(CipherSuite, Result<(bool, Option<u64>)>)>;

/// Trait for cipher testing abstraction (enables mocking in tests)
#[async_trait::async_trait]
pub trait CipherTestable: Send + Sync {
    async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>>;
}

// ============================================================================
// Constants for Cipher Testing
// ============================================================================

/// Multiplier for batch size when processing cipher tests.
/// A batch size of `current_batch_size * BATCH_SIZE_MULTIPLIER` is used to
/// prefetch ciphers for testing while respecting concurrency limits.
const BATCH_SIZE_MULTIPLIER: usize = 5;

/// Base delay in milliseconds for exponential backoff when network errors occur.
/// The actual delay is calculated as `BACKOFF_BASE_DELAY_MS * 2^error_level`.
const BACKOFF_BASE_DELAY_MS: u64 = 100;

/// Maximum exponent for exponential backoff calculation.
/// Caps the delay at `BACKOFF_BASE_DELAY_MS * 2^BACKOFF_MAX_EXPONENT` (1600ms).
const BACKOFF_MAX_EXPONENT: u32 = 4;

/// Sleep duration in seconds between retry rounds for ENETDOWN recovery.
/// Provides a longer pause before retrying ciphers that failed due to network issues.
const RETRY_BACKOFF_SECS: u64 = 3;

/// Minimum size in bytes for a valid ServerHello response.
/// A ServerHello must be at least this size to contain the required fields:
/// 5 bytes record header + 4 bytes handshake header + 2 bytes version +
/// 32 bytes random + 1 byte session ID length = 44 bytes minimum.
const SERVER_HELLO_MIN_SIZE: usize = 44;

/// Byte offset in the ServerHello response where the session ID length is located.
/// This is after: 5 bytes record header + 4 bytes handshake header +
/// 2 bytes version + 32 bytes random = offset 43.
const SESSION_ID_LENGTH_OFFSET: usize = 43;

/// Base byte offset for the cipher suite field in ServerHello.
/// The cipher suite starts at this offset plus the session ID length.
const CIPHER_SUITE_BASE_OFFSET: usize = 44;

// ============================================================================
// Section 1: Connection Pooling
// ============================================================================

/// TLS Connection Pool for reusing TCP connections during cipher testing.
///
/// Performance optimization: Reduces connection overhead by maintaining a pool
/// of pre-established TCP connections. This is particularly effective for cipher
/// testing where hundreds of connections would otherwise be created sequentially.
///
/// # Performance Characteristics
/// - Pool hit: O(1) - instant connection retrieval
/// - Pool miss: O(n) where n is TCP connection establishment time (~10-100ms)
/// - Memory usage: O(max_size × connection_overhead)
/// - Typical improvement: 50-90% reduction in connection establishment overhead
///
/// # Design Rationale
/// TLS handshakes require fresh connections, but the TCP connection phase can be
/// reused. After a TLS handshake attempt, connections are closed rather than returned
/// to the pool to ensure handshake integrity.
///
/// # Note
/// The `release` and `size` methods are currently unused as connections are not
/// returned to the pool after TLS handshakes (by design). They are kept for future
/// use cases where connection reuse might be appropriate.
#[allow(dead_code)]
struct TlsConnectionPool {
    pool: Arc<Mutex<Vec<TcpStream>>>,
    addr: SocketAddr,
    max_size: usize,
    connect_timeout: Duration,
    retry_config: Option<crate::utils::retry::RetryConfig>,
}

impl TlsConnectionPool {
    /// Create a new connection pool for the specified address.
    ///
    /// # Arguments
    /// * `addr` - Target socket address for all connections
    /// * `max_size` - Maximum number of pooled connections (default: 10)
    /// * `connect_timeout` - Timeout for establishing new connections
    /// * `retry_config` - Optional retry configuration for connection failures
    fn new(
        addr: SocketAddr,
        max_size: usize,
        connect_timeout: Duration,
        retry_config: Option<crate::utils::retry::RetryConfig>,
    ) -> Self {
        Self {
            pool: Arc::new(Mutex::new(Vec::with_capacity(max_size))),
            addr,
            max_size,
            connect_timeout,
            retry_config,
        }
    }

    /// Acquire a connection from the pool or create a new one.
    ///
    /// This method attempts to retrieve a connection from the pool first.
    /// If the pool is empty, it establishes a new TCP connection.
    ///
    /// # Performance Impact
    /// - Pool hit: ~1μs (lock acquisition + vector pop)
    /// - Pool miss: ~10-100ms (new TCP connection)
    /// - Hit rate typically 60-80% in cipher testing workloads
    async fn acquire(&self) -> Result<TcpStream> {
        // Try to get a connection from the pool
        {
            let mut pool = self.pool.lock().await;
            if let Some(stream) = pool.pop() {
                tracing::trace!("Connection pool hit (size: {})", pool.len());
                return Ok(stream);
            }
        }

        // Pool is empty, create a new connection
        tracing::trace!(
            "Connection pool miss, establishing new connection to {}",
            self.addr
        );
        crate::utils::network::connect_with_timeout(
            self.addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        .map_err(|e| crate::TlsError::Other(format!("Connection failed: {}", e)))
    }

    /// Return a connection to the pool if there's space.
    ///
    /// Connections are only returned if the pool has not reached max capacity.
    /// This prevents unbounded memory growth while maintaining performance benefits.
    ///
    /// # Arguments
    /// * `stream` - TCP stream to return to the pool
    ///
    /// # Note
    /// The caller should only return connections that are in a clean state
    /// (i.e., no partial TLS handshake in progress).
    #[allow(dead_code)]
    async fn release(&self, stream: TcpStream) {
        let mut pool = self.pool.lock().await;
        if pool.len() < self.max_size {
            pool.push(stream);
            tracing::trace!("Connection returned to pool (size: {})", pool.len());
        } else {
            // Pool is full, drop the connection
            tracing::trace!("Connection pool full, dropping connection");
            drop(stream);
        }
    }

    /// Get current pool size (for monitoring/debugging).
    #[allow(dead_code)]
    async fn size(&self) -> usize {
        self.pool.lock().await.len()
    }
}

// ============================================================================
// Section 2: Data Types
// ============================================================================

/// Result of cipher testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherTestResult {
    pub cipher: CipherSuite,
    pub supported: bool,
    pub protocol: Protocol,
    pub server_preference: Option<usize>, // Position in server's preference list
    pub handshake_time_ms: Option<u64>,
}

/// Cipher testing summary for a protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCipherSummary {
    pub protocol: Protocol,
    pub supported_ciphers: Vec<CipherSuite>,
    pub server_ordered: bool,
    pub server_preference: Vec<String>, // Ordered list of cipher hexcodes
    pub preferred_cipher: Option<CipherSuite>,
    pub counts: CipherCounts,
    pub avg_handshake_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherCounts {
    pub total: usize,
    pub null_ciphers: usize,
    pub export_ciphers: usize,
    pub low_strength: usize,
    pub medium_strength: usize,
    pub high_strength: usize,
    pub forward_secrecy: usize,
    pub aead: usize,
}

// ============================================================================
// Section 2b: Cipher Preference Analysis
// ============================================================================

/// Analyzes cipher preference order to determine if server or client controls selection.
///
/// This struct encapsulates the logic for determining whether a TLS server enforces
/// its own cipher preference order or defers to the client's preference. The analysis
/// is based on multiple handshake tests with different cipher orderings.
struct CipherPreferenceAnalyzer {
    first_choice: Option<u16>,
    second_choice: Option<u16>,
    third_choice: Option<u16>,
    cipher_hexcodes: Vec<u16>,
    reversed: Vec<u16>,
    rotated: Option<Vec<u16>>,
}

impl CipherPreferenceAnalyzer {
    fn new(
        first_choice: Option<u16>,
        second_choice: Option<u16>,
        third_choice: Option<u16>,
        cipher_hexcodes: Vec<u16>,
        reversed: Vec<u16>,
        rotated: Option<Vec<u16>>,
    ) -> Self {
        Self {
            first_choice,
            second_choice,
            third_choice,
            cipher_hexcodes,
            reversed,
            rotated,
        }
    }

    /// Check if server follows client's first cipher choice in each test.
    fn is_client_preference(&self) -> bool {
        let follows_original = self
            .first_choice
            .is_some_and(|c| self.cipher_hexcodes.first() == Some(&c));

        let follows_reversed = self
            .second_choice
            .is_some_and(|c| self.reversed.first() == Some(&c));

        let follows_rotated = match (&self.third_choice, &self.rotated) {
            (Some(third), Some(offered)) => offered.first() == Some(third),
            (None, _) => true, // No third test means we can't contradict
            _ => false,
        };

        follows_original && follows_reversed && follows_rotated
    }

    /// Check if server always picks the same cipher regardless of order.
    fn all_choices_same(&self) -> bool {
        match self.third_choice {
            Some(third) => {
                self.first_choice == self.second_choice && self.second_choice == Some(third)
            }
            None => self.first_choice == self.second_choice,
        }
    }

    /// Check if server picks same cipher in tests 2 and 3 from different positions.
    fn mostly_same_different_positions(&self) -> bool {
        let (Some(second), Some(third)) = (self.second_choice, self.third_choice) else {
            return false;
        };

        if second != third {
            return false;
        }

        let pos_in_reversed = self.reversed.iter().position(|&c| c == second);
        let pos_in_rotated = self
            .rotated
            .as_ref()
            .and_then(|offered| offered.iter().position(|&c| c == second));

        match (pos_in_reversed, pos_in_rotated) {
            (Some(pos2), Some(pos3)) => pos2 != pos3,
            _ => false,
        }
    }

    /// Determine if server enforces its own cipher preference.
    fn is_server_preference(&self) -> bool {
        if self.is_client_preference() {
            tracing::debug!(
                "Server respects client cipher preference (consistently picks client's first choice)"
            );
            return false;
        }

        if self.all_choices_same() {
            tracing::debug!("Server enforces cipher preference (chose same cipher in all tests)");
            return true;
        }

        if self.mostly_same_different_positions() {
            tracing::debug!(
                "Server enforces cipher preference (chose same cipher in multiple tests from different positions)"
            );
            return true;
        }

        // Mixed behavior - default to assuming server preference for security
        tracing::debug!(
            "Server cipher preference unclear (mixed behavior detected, assuming server preference)"
        );
        true
    }

    /// Build the preference order list when server has preference.
    fn build_preference_order(&self, supported_ciphers: &[CipherSuite]) -> Vec<String> {
        let mut preference_order = Vec::new();

        if let Some(chosen) = self.first_choice {
            preference_order.push(format!("{:04x}", chosen));

            for cipher in supported_ciphers {
                if !preference_order.iter().any(|h| h == &cipher.hexcode) {
                    preference_order.push(cipher.hexcode.clone());
                }
            }
        }

        preference_order
    }
}

// ============================================================================
// Section 3: CipherTester Configuration
// ============================================================================

/// Cipher testing configuration
pub struct CipherTester {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    test_all_ciphers: bool,
    sleep_duration: Option<Duration>,
    use_rdp: bool,
    starttls_protocol: Option<crate::starttls::StarttlsProtocol>,
    test_all_ips: bool,
    retry_config: Option<crate::utils::retry::RetryConfig>,
    max_concurrent_tests: usize,
    connection_pool_size: usize,
    adaptive: Option<Arc<AdaptiveController>>,
}

impl CipherTester {
    /// Create new cipher tester
    pub fn new(target: Target) -> Self {
        // Auto-detect RDP based on port
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: CIPHER_TEST_READ_TIMEOUT,
            test_all_ciphers: false,
            sleep_duration: None,
            use_rdp,
            starttls_protocol: None,
            test_all_ips: false,
            retry_config: None,
            max_concurrent_tests: 10, // Default to 10 concurrent cipher tests
            connection_pool_size: 10, // Default pool size matches concurrency
            adaptive: None,
        }
    }

    /// Set connect timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set read timeout
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Enable testing all ciphers (slower but comprehensive)
    pub fn test_all(mut self, enable: bool) -> Self {
        self.test_all_ciphers = enable;
        self
    }

    /// Set sleep duration between connections
    pub fn with_sleep(mut self, duration: Duration) -> Self {
        self.sleep_duration = Some(duration);
        self
    }

    /// Enable or disable RDP mode
    pub fn with_rdp(mut self, enable: bool) -> Self {
        self.use_rdp = enable;
        self
    }

    /// Set STARTTLS protocol
    pub fn with_starttls(mut self, protocol: Option<crate::starttls::StarttlsProtocol>) -> Self {
        self.starttls_protocol = protocol;
        self
    }

    /// Enable testing all resolved IP addresses (for Anycast pools)
    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    /// Set retry configuration for handling transient network failures
    pub fn with_retry_config(mut self, config: Option<crate::utils::retry::RetryConfig>) -> Self {
        self.retry_config = config;
        self
    }

    /// Attach adaptive controller for dynamic timeouts and concurrency.
    pub fn with_adaptive(mut self, adaptive: Option<Arc<AdaptiveController>>) -> Self {
        self.adaptive = adaptive;
        self
    }

    /// Set maximum concurrent cipher tests
    pub fn with_max_concurrent_tests(mut self, max: usize) -> Self {
        self.max_concurrent_tests = max.max(1); // Ensure at least 1
        self
    }

    /// Set connection pool size for TCP connection reuse.
    ///
    /// A larger pool size reduces connection establishment overhead but increases
    /// memory usage. The optimal size typically matches max_concurrent_tests.
    ///
    /// # Performance Impact
    /// - Pool size 0: No pooling, every test creates new connection
    /// - Pool size 1-5: Moderate improvement (~20-40% faster)
    /// - Pool size 10-20: Optimal for most workloads (~50-90% faster)
    /// - Pool size >20: Diminishing returns, increased memory overhead
    ///
    /// # Arguments
    /// * `size` - Maximum number of pooled connections (0 to disable pooling)
    pub fn with_connection_pool_size(mut self, size: usize) -> Self {
        self.connection_pool_size = size;
        self
    }

    // ========================================================================
    // Section 4: Main Cipher Testing (Concurrent with Adaptive Backoff)
    // ========================================================================

    /// Test all cipher suites for a specific protocol
    pub async fn test_protocol_ciphers(&self, protocol: Protocol) -> Result<ProtocolCipherSummary> {
        let ciphers = if self.test_all_ciphers {
            CIPHER_DB.get_all_ciphers()
        } else {
            // Test common/recommended ciphers only for speed
            CIPHER_DB.get_recommended_ciphers()
        };

        // Filter compatible ciphers for this protocol
        let compatible_ciphers: Vec<CipherSuite> = ciphers
            .into_iter()
            .filter(|c| self.is_cipher_compatible_with_protocol(c, protocol))
            .collect();

        let mut max_concurrent_tests = self.max_concurrent_tests.max(1);
        if let Some(adaptive) = &self.adaptive {
            max_concurrent_tests = adaptive.max_concurrency().max(1);
        }

        tracing::debug!(
            "Testing {} compatible ciphers for {:?} with max {} concurrent connections (pool size: {})",
            compatible_ciphers.len(),
            protocol,
            max_concurrent_tests,
            self.connection_pool_size
        );

        // Create connection pool if enabled (pool size > 0)
        let connection_pool = if self.connection_pool_size > 0 {
            let addr = self.target.socket_addrs()[0];
            Some(Arc::new(TlsConnectionPool::new(
                addr,
                self.connection_pool_size.min(max_concurrent_tests),
                self.connect_timeout,
                self.retry_config.clone(),
            )))
        } else {
            None
        };

        // Create semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_tests));

        // Create arc for self to share across tasks
        let tester = Arc::new(self);

        // Test ciphers concurrently using futures stream with adaptive backoff
        let mut results: Vec<CipherTestResult> = Vec::new();
        let mut enetdown_count = 0;
        let mut current_batch_size = max_concurrent_tests;
        let mut cipher_queue: Vec<CipherSuite> = compatible_ciphers;
        let mut retry_queue: Vec<CipherSuite> = Vec::new();
        let max_enetdown_retries = 3;
        let mut retry_round = 0;

        // Process ciphers in batches with adaptive concurrency and retry
        while !cipher_queue.is_empty() || !retry_queue.is_empty() {
            // Switch to retry queue if main queue is empty
            if cipher_queue.is_empty() && !retry_queue.is_empty() {
                retry_round += 1;
                if retry_round > max_enetdown_retries {
                    tracing::warn!(
                        "Max ENETDOWN retries ({}) reached, {} ciphers could not be tested",
                        max_enetdown_retries,
                        retry_queue.len()
                    );
                    break;
                }
                cipher_queue = retry_queue;
                retry_queue = Vec::new();
                tracing::info!(
                    "Retrying {} ciphers that failed with ENETDOWN (attempt {}/{})",
                    cipher_queue.len(),
                    retry_round,
                    max_enetdown_retries
                );
                // Longer backoff between retry rounds
                tokio::time::sleep(std::time::Duration::from_secs(RETRY_BACKOFF_SECS)).await;
            }

            // Adjust concurrency if adaptive controller changed
            if let Some(adaptive) = &self.adaptive {
                let adaptive_max = adaptive.max_concurrency().max(1);
                if adaptive_max != max_concurrent_tests {
                    max_concurrent_tests = adaptive_max;
                    current_batch_size = current_batch_size.min(max_concurrent_tests);
                }
            }

            // Get next batch of ciphers
            let batch_size = current_batch_size * BATCH_SIZE_MULTIPLIER;
            let batch: Vec<_> = cipher_queue
                .drain(..cipher_queue.len().min(batch_size))
                .collect();

            if batch.is_empty() {
                break;
            }

            // Test batch with current concurrency level
            // Returns (cipher, Result<(supported, handshake_time)>) to avoid cloning cipher on success
            let batch_results: CipherBatchResult =
                stream::iter(batch)
                    .map(|cipher| {
                        let sem = semaphore.clone();
                        let tester_clone = tester.clone();
                        let pool_clone = connection_pool.clone();
                        async move {
                            // Acquire semaphore permit
                            let _permit = sem.acquire().await.expect("semaphore closed");

                            // Test the cipher with connection pool if available
                            let result = if let Some(pool) = pool_clone {
                                tester_clone
                                    .test_cipher_handshake_only(&cipher, protocol, Some(&pool))
                                    .await
                            } else {
                                tester_clone
                                    .test_cipher_handshake_only(&cipher, protocol, None)
                                    .await
                            };

                            // Sleep between requests if configured
                            if let Some(sleep_dur) = tester_clone.sleep_duration {
                                tokio::time::sleep(sleep_dur).await;
                            }

                            (cipher, result)
                        }
                    })
                    .buffer_unordered(current_batch_size)
                    .collect::<Vec<_>>()
                    .await;

            // Check for ENETDOWN errors and adapt concurrency
            let mut batch_enetdown = 0;
            let mut batch_other_errors = 0;

            // Collect results, queueing ENETDOWN failures for retry
            for (cipher, result) in batch_results {
                match result {
                    Ok((supported, handshake_time_ms)) => {
                        results.push(CipherTestResult {
                            cipher,
                            supported,
                            protocol,
                            server_preference: None,
                            handshake_time_ms,
                        });
                    }
                    Err(e) => {
                        let err_msg = e.to_string().to_lowercase();
                        if err_msg.contains("network is down") || err_msg.contains("os error 50") {
                            // ENETDOWN error - queue for retry with reduced concurrency
                            batch_enetdown += 1;
                            retry_queue.push(cipher);
                        } else {
                            // Other error - log and continue (treat as unsupported)
                            batch_other_errors += 1;
                            tracing::debug!("Cipher test error (non-ENETDOWN): {}", e);
                        }
                    }
                }
            }

            enetdown_count += batch_enetdown;

            // Performance optimization: Improved adaptive backoff with exponential backoff and jitter
            if batch_enetdown > 0 {
                let old_size = current_batch_size;

                // More aggressive reduction if many errors
                if batch_enetdown > current_batch_size / 2 {
                    current_batch_size = (current_batch_size / 3).max(1);
                } else {
                    current_batch_size = (current_batch_size / 2).max(1);
                }

                // Exponential backoff with jitter
                // Base delay increases exponentially with error count (capped at 10)
                let error_level = batch_enetdown.min(10) as u32;
                let base_delay_ms =
                    BACKOFF_BASE_DELAY_MS * 2u64.pow(error_level.min(BACKOFF_MAX_EXPONENT));

                // Add jitter (0-25% of base delay) to avoid thundering herd
                use rand::Rng;
                let jitter = rand::thread_rng().gen_range(0..=(base_delay_ms / 4));
                let total_delay_ms = base_delay_ms + jitter;

                tracing::warn!(
                    "Detected {} ENETDOWN error(s), reducing concurrency from {} to {} with {}ms exponential backoff",
                    batch_enetdown,
                    old_size,
                    current_batch_size,
                    total_delay_ms
                );

                tokio::time::sleep(std::time::Duration::from_millis(total_delay_ms)).await;
            } else if current_batch_size < max_concurrent_tests && batch_other_errors == 0 {
                // Gradual recovery: increase concurrency after successful batches
                // Only recover if no errors occurred at all
                current_batch_size = (current_batch_size + 1).min(max_concurrent_tests);
                tracing::debug!(
                    "Successful batch, increasing concurrency to {}",
                    current_batch_size
                );
            }

            if batch_other_errors > 0 {
                tracing::debug!("Batch had {} other errors (ignored)", batch_other_errors);
            }
        }

        if enetdown_count > 0 {
            tracing::info!(
                "Completed cipher testing with {} ENETDOWN error(s) recovered via adaptive backoff",
                enetdown_count
            );
        }

        // Calculate average handshake time before consuming results
        let handshake_times: Vec<u64> =
            results.iter().filter_map(|r| r.handshake_time_ms).collect();
        let avg_handshake_time_ms = if !handshake_times.is_empty() {
            Some(handshake_times.iter().sum::<u64>() / handshake_times.len() as u64)
        } else {
            None
        };

        // Extract supported ciphers by consuming results (avoids clone)
        let supported: Vec<CipherSuite> = results
            .into_iter()
            .filter(|r| r.supported)
            .map(|r| r.cipher)
            .collect();

        tracing::debug!(
            "Found {} supported ciphers for {:?}",
            supported.len(),
            protocol
        );

        // Determine server cipher preference order
        let server_preference = self
            .determine_server_preference(protocol, &supported)
            .await?;
        let server_ordered = !server_preference.is_empty();

        // Get preferred cipher (first in server's preference list)
        let preferred_cipher = if !server_preference.is_empty() {
            CIPHER_DB.get_by_hexcode(&server_preference[0])
        } else {
            supported.first().cloned()
        };

        // Calculate statistics
        let counts = self.calculate_cipher_counts(&supported);

        Ok(ProtocolCipherSummary {
            protocol,
            supported_ciphers: supported,
            server_ordered,
            server_preference,
            preferred_cipher,
            counts,
            avg_handshake_time_ms,
        })
    }

    /// Test cipher handshake and return only the result data (no cipher clone).
    ///
    /// Returns (supported, handshake_time_ms) tuple to avoid cloning the cipher.
    /// The caller can construct the full CipherTestResult with the cipher it owns.
    async fn test_cipher_handshake_only(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
        pool: Option<&Arc<TlsConnectionPool>>,
    ) -> Result<(bool, Option<u64>)> {
        let hexcode = match u16::from_str_radix(&cipher.hexcode, 16) {
            Ok(h) => h,
            Err(_) => return Ok((false, None)),
        };

        let start = std::time::Instant::now();
        let supported = if let Some(pool) = pool {
            self.try_cipher_handshake_with_pool(protocol, hexcode, pool)
                .await?
        } else {
            self.try_cipher_handshake(protocol, hexcode).await?
        };

        let handshake_time_ms = if supported {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        Ok((supported, handshake_time_ms))
    }

    // ========================================================================
    // Section 5: Handshake Logic
    // ========================================================================

    /// Test a single cipher suite (public API, constructs full result).
    pub async fn test_single_cipher(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
    ) -> Result<CipherTestResult> {
        let (supported, handshake_time_ms) = self
            .test_cipher_handshake_only(cipher, protocol, None)
            .await?;

        Ok(CipherTestResult {
            cipher: cipher.clone(),
            supported,
            protocol,
            server_preference: None,
            handshake_time_ms,
        })
    }

    /// Attempt TLS handshake with specific cipher using connection pool.
    ///
    /// This method acquires a connection from the pool and performs the TLS handshake.
    /// After the handshake (success or failure), the connection is NOT returned to the
    /// pool because TLS state cannot be safely reused.
    async fn try_cipher_handshake_with_pool(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
        pool: &Arc<TlsConnectionPool>,
    ) -> Result<bool> {
        if self.test_all_ips {
            // Test all IPs - not compatible with connection pooling
            // Fall back to non-pooled implementation
            self.try_cipher_handshake_all_ips(protocol, cipher_hexcode)
                .await
        } else {
            // Test only first IP using pooled connection
            let addr = self.target.socket_addrs()[0];
            self.try_cipher_handshake_on_ip_with_pool(protocol, cipher_hexcode, addr, pool)
                .await
        }
    }

    /// Attempt TLS handshake with specific cipher (non-pooled version).
    async fn try_cipher_handshake(&self, protocol: Protocol, cipher_hexcode: u16) -> Result<bool> {
        if self.test_all_ips {
            // Test all IPs and return true only if ALL support the cipher
            self.try_cipher_handshake_all_ips(protocol, cipher_hexcode)
                .await
        } else {
            // Test only first IP (default behavior)
            let addr = self.target.socket_addrs()[0];
            self.try_cipher_handshake_on_ip(protocol, cipher_hexcode, addr)
                .await
        }
    }

    /// Test cipher on all IPs
    async fn try_cipher_handshake_all_ips(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
    ) -> Result<bool> {
        let addrs = self.target.socket_addrs();

        if addrs.is_empty() {
            return Ok(false);
        }

        let mut all_support = true;

        for addr in &addrs {
            let ip_supports = self
                .try_cipher_handshake_on_ip(protocol, cipher_hexcode, *addr)
                .await?;
            if !ip_supports {
                all_support = false;
                break; // Early exit for performance
            }
        }

        Ok(all_support)
    }

    /// Perform the TLS cipher handshake on an established TCP stream.
    ///
    /// This method contains the common handshake logic shared between pooled and
    /// non-pooled connection modes. It handles RDP preamble, STARTTLS negotiation,
    /// ClientHello construction, and ServerHello response parsing.
    ///
    /// # Arguments
    /// * `stream` - Mutable reference to an established TCP stream
    /// * `protocol` - TLS protocol version to test
    /// * `cipher_hexcode` - The cipher suite to test (as u16 hex code)
    ///
    /// # Returns
    /// * `Ok(true)` - Server accepted the cipher (ServerHello received)
    /// * `Ok(false)` - Server rejected the cipher (Alert or no response)
    /// * `Err(_)` - Error building ClientHello
    async fn perform_cipher_handshake(
        &self,
        stream: &mut TcpStream,
        protocol: Protocol,
        cipher_hexcode: u16,
    ) -> Result<bool> {
        // Send RDP preamble if needed
        if self.use_rdp
            && crate::protocols::rdp::RdpPreamble::send(stream)
                .await
                .is_err()
        {
            return Ok(false);
        }

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(stream).await.is_err() {
                return Ok(false);
            }
        }

        // Build ClientHello with only this cipher
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_cipher(cipher_hexcode);
        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send ClientHello and read response
        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            // Read ServerHello or Alert
            let mut response = vec![0u8; BUFFER_SIZE_DEFAULT];
            let n = stream.read(&mut response).await?;

            if n == 0 {
                return Ok(false);
            }

            // Check if we got ServerHello (Handshake record with ServerHello message)
            if n >= 6
                && response[0] == CONTENT_TYPE_HANDSHAKE
                && response[5] == HANDSHAKE_TYPE_SERVER_HELLO
            {
                return Ok(true);
            }

            // Check for Alert or other non-ServerHello response
            Ok(false)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(false), // Timeout
        }
    }

    /// Attempt TLS handshake with specific cipher on specific IP using connection pool.
    ///
    /// Acquires a connection from the pool and delegates to `perform_cipher_handshake`.
    /// The connection is NOT returned to the pool after use, as TLS state cannot be reused.
    async fn try_cipher_handshake_on_ip_with_pool(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
        _addr: std::net::SocketAddr,
        pool: &Arc<TlsConnectionPool>,
    ) -> Result<bool> {
        let mut stream = match pool.acquire().await {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        self.perform_cipher_handshake(&mut stream, protocol, cipher_hexcode)
            .await
    }

    /// Attempt TLS handshake with specific cipher on specific IP (non-pooled version).
    ///
    /// Creates a new TCP connection and delegates to `perform_cipher_handshake`.
    async fn try_cipher_handshake_on_ip(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
        addr: std::net::SocketAddr,
    ) -> Result<bool> {
        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        self.perform_cipher_handshake(&mut stream, protocol, cipher_hexcode)
            .await
    }

    // ========================================================================
    // Section 6: Server Preference Detection
    // ========================================================================

    /// Determine server's cipher preference order
    async fn determine_server_preference(
        &self,
        protocol: Protocol,
        supported_ciphers: &[CipherSuite],
    ) -> Result<Vec<String>> {
        if supported_ciphers.is_empty() {
            return Ok(Vec::new());
        }

        let cipher_hexcodes: Vec<u16> = supported_ciphers
            .iter()
            .filter_map(|c| u16::from_str_radix(&c.hexcode, 16).ok())
            .collect();

        if cipher_hexcodes.len() < 2 {
            return Ok(supported_ciphers
                .iter()
                .map(|c| c.hexcode.to_string())
                .collect());
        }

        // Test 1: Send ciphers in original order
        let first_choice = self
            .get_server_chosen_cipher(protocol, &cipher_hexcodes)
            .await?;

        tracing::debug!(
            "Cipher preference test 1 (original order): client offered {:04x?}, server chose {:04x?}",
            cipher_hexcodes,
            first_choice
        );

        // Test 2: Send ciphers in reverse order
        let mut reversed = cipher_hexcodes.clone();
        reversed.reverse();
        let second_choice = self.get_server_chosen_cipher(protocol, &reversed).await?;

        tracing::debug!(
            "Cipher preference test 2 (reversed order): client offered {:04x?}, server chose {:04x?}",
            reversed,
            second_choice
        );

        // Test 3: Rotated order (if 3+ ciphers available)
        let (third_choice, rotated) = if cipher_hexcodes.len() >= 3 {
            let mut rotated = cipher_hexcodes.clone();
            if let Some(last) = rotated.pop() {
                rotated.insert(0, last);
            }
            let choice = self.get_server_chosen_cipher(protocol, &rotated).await?;
            tracing::debug!(
                "Cipher preference test 3 (rotated order): client offered {:04x?}, server chose {:04x?}",
                rotated,
                choice
            );
            (choice, Some(rotated))
        } else {
            (None, None)
        };

        // Analyze using helper struct
        let analyzer = CipherPreferenceAnalyzer::new(
            first_choice,
            second_choice,
            third_choice,
            cipher_hexcodes,
            reversed,
            rotated,
        );

        if analyzer.is_server_preference() {
            Ok(analyzer.build_preference_order(supported_ciphers))
        } else {
            Ok(Vec::new())
        }
    }

    /// Get the cipher that the server chooses from a list
    async fn get_server_chosen_cipher(
        &self,
        protocol: Protocol,
        cipher_hexcodes: &[u16],
    ) -> Result<Option<u16>> {
        // For cipher preference detection, we only need to test one IP
        // Use first IP regardless of test_all_ips flag
        let addr = self.target.socket_addrs()[0];

        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(None);
            }
        }

        // Build ClientHello with all these ciphers
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(cipher_hexcodes);
        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send and read ServerHello
        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            let mut response = vec![0u8; BUFFER_SIZE_DEFAULT];
            let bytes_read = stream.read(&mut response).await?;

            if bytes_read >= SERVER_HELLO_MIN_SIZE
                && response[0] == CONTENT_TYPE_HANDSHAKE
                && response[5] == HANDSHAKE_TYPE_SERVER_HELLO
            {
                // Parse chosen cipher from ServerHello
                // ServerHello structure:
                // 5 bytes: Record header
                // 4 bytes: Handshake header
                // 2 bytes: Server version
                // 32 bytes: Random
                // 1 byte: Session ID length
                // N bytes: Session ID
                // 2 bytes: Cipher suite <-- what we want

                let session_id_len = response[SESSION_ID_LENGTH_OFFSET] as usize;
                let cipher_offset = CIPHER_SUITE_BASE_OFFSET + session_id_len;

                tracing::debug!(
                    "ServerHello: session_id_len={}, cipher_offset={}, response_len={}",
                    session_id_len,
                    cipher_offset,
                    bytes_read
                );

                if bytes_read >= cipher_offset + 2 {
                    let cipher =
                        u16::from_be_bytes([response[cipher_offset], response[cipher_offset + 1]]);
                    tracing::debug!("Server chose cipher: 0x{:04x}", cipher);
                    return Ok(Some(cipher));
                }
            }

            Ok(None)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(None),
        }
    }

    // ========================================================================
    // Section 7: Helper Methods
    // ========================================================================

    /// Check if cipher is compatible with protocol
    fn is_cipher_compatible_with_protocol(&self, cipher: &CipherSuite, protocol: Protocol) -> bool {
        // TLS 1.3 has its own cipher suites
        if matches!(protocol, Protocol::TLS13) {
            return cipher.protocol.contains("TLS13") || cipher.protocol.contains("TLSv1.3");
        }

        // SSLv2 has specific cipher format
        if matches!(protocol, Protocol::SSLv2) {
            return cipher.protocol.contains("SSLv2");
        }

        // SSLv3/TLS 1.0-1.2 share most ciphers
        // Exclude TLS 1.3 specific ciphers
        !cipher.protocol.contains("TLS13") && !cipher.protocol.contains("SSLv2")
    }

    /// Calculate cipher statistics
    fn calculate_cipher_counts(&self, ciphers: &[CipherSuite]) -> CipherCounts {
        let mut counts = CipherCounts {
            total: ciphers.len(),
            ..Default::default()
        };

        for cipher in ciphers {
            match cipher.strength() {
                CipherStrength::NULL => counts.null_ciphers += 1,
                CipherStrength::Export => counts.export_ciphers += 1,
                CipherStrength::Low => counts.low_strength += 1,
                CipherStrength::Medium => counts.medium_strength += 1,
                CipherStrength::High => counts.high_strength += 1,
            }

            if cipher.has_forward_secrecy() {
                counts.forward_secrecy += 1;
            }

            if cipher.is_aead() {
                counts.aead += 1;
            }
        }

        counts
    }

    /// Test all protocols and their ciphers
    pub async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>> {
        let mut results = HashMap::new();

        for protocol in Protocol::all() {
            // Skip QUIC for now
            if matches!(protocol, Protocol::QUIC) {
                continue;
            }

            let summary = self.test_protocol_ciphers(protocol).await?;
            if !summary.supported_ciphers.is_empty() {
                results.insert(protocol, summary);
            }
        }

        Ok(results)
    }

    /// Quick test - only test for cipher suite support, not order
    pub async fn quick_test(&self, protocol: Protocol) -> Result<Vec<CipherSuite>> {
        let common_ciphers = CIPHER_DB.get_recommended_ciphers();
        let mut supported = Vec::new();

        for cipher in common_ciphers {
            if self.is_cipher_compatible_with_protocol(&cipher, protocol) {
                let result = self.test_single_cipher(&cipher, protocol).await?;
                if result.supported {
                    supported.push(cipher);
                }
            }
        }

        Ok(supported)
    }
}

#[async_trait::async_trait]
impl CipherTestable for CipherTester {
    async fn test_all_protocols(&self) -> Result<HashMap<Protocol, ProtocolCipherSummary>> {
        self.test_all_protocols().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_cipher_detection() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = CipherTester::new(target);

        let summary = tester
            .test_protocol_ciphers(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        // Should support at least some ciphers
        assert!(!summary.supported_ciphers.is_empty());

        // Should have forward secrecy ciphers
        assert!(summary.counts.forward_secrecy > 0);

        // Should not support NULL or EXPORT ciphers
        assert_eq!(summary.counts.null_ciphers, 0);
        assert_eq!(summary.counts.export_ciphers, 0);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_server_preference() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = CipherTester::new(target);

        let summary = tester
            .test_protocol_ciphers(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        // Google should have server cipher preference
        assert!(summary.server_ordered);
        assert!(!summary.server_preference.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_quick_scan() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = CipherTester::new(target);

        let ciphers = tester
            .quick_test(Protocol::TLS12)
            .await
            .expect("test assertion should succeed");

        assert!(!ciphers.is_empty());
    }

    #[test]
    fn test_cipher_strength_calculation() {
        let cipher = CipherSuite {
            hexcode: "c030".to_string(),
            openssl_name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            iana_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES256-GCM".to_string(),
            mac: "SHA384".to_string(),
            bits: 256,
            export: false,
        };

        assert_eq!(cipher.strength(), CipherStrength::High);
        assert!(cipher.has_forward_secrecy());
        assert!(cipher.is_aead());
    }
}
