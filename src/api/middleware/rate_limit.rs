// Rate Limiting Middleware

use crate::api::{
    config::Permission, middleware::auth::AuthExtension, models::error::RateLimitErrorResponse,
    state::AppState,
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use governor::{
    Quota, RateLimiter as GovernorRateLimiter,
    clock::{Clock, DefaultClock},
    middleware::StateInformationMiddleware,
    state::{InMemoryState, NotKeyed},
};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Mask an API key for safe logging (shows first 4 and last 4 characters)
fn mask_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() > 8 {
        let first: String = chars.iter().take(4).collect();
        let last: String = chars.iter().rev().take(4).rev().collect();
        format!("{}...{}", first, last)
    } else if chars.len() > 4 {
        let first: String = chars.iter().take(4).collect();
        format!("{}****", first)
    } else {
        "****".to_string()
    }
}

/// Type alias for the governor rate limiter with state information middleware
/// This allows us to get remaining capacity information after each check
type Limiter =
    Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock, StateInformationMiddleware>>;

/// Entry with rate limiter and last access timestamp for LRU eviction
struct RateLimitEntry {
    limiter: Limiter,
    last_access: Instant,
}

/// Per-key rate limiter storage with efficient LRU eviction
pub struct PerKeyRateLimiter {
    /// Storage for per-key rate limiters with timestamps
    limiters: Arc<DashMap<String, RateLimitEntry>>,
    /// Index for efficient LRU eviction: timestamp -> keys
    /// Uses BTreeMap for O(log n) access to oldest entries
    access_index: Arc<RwLock<BTreeMap<Instant, Vec<String>>>>,
    /// Default quota configuration
    default_quota: Quota,
    /// Requests per minute limit
    requests_per_minute: u32,
    /// Window duration in seconds
    window_seconds: u64,
}

impl PerKeyRateLimiter {
    /// Create new per-key rate limiter
    pub fn new(requests_per_minute: u32) -> Self {
        // Ensure we have a valid non-zero value, defaulting to 100 if invalid
        let rpm = NonZeroU32::new(requests_per_minute)
            .unwrap_or_else(|| NonZeroU32::new(100).expect("100 is always non-zero"));
        let default_quota = Quota::per_minute(rpm);
        // Store the actual RPM value used (may differ from input if input was 0)
        let effective_rpm = rpm.get();

        Self {
            limiters: Arc::new(DashMap::new()),
            access_index: Arc::new(RwLock::new(BTreeMap::new())),
            default_quota,
            requests_per_minute: effective_rpm,
            window_seconds: 60,
        }
    }

    /// Check rate limit for a specific key and return rate limit info
    ///
    /// Uses Governor as the single source of truth for rate limiting decisions.
    /// Remaining is calculated from Governor's StateInformationMiddleware which
    /// provides accurate remaining capacity without race conditions.
    ///
    /// The timestamp is updated atomically with the limiter access to ensure
    /// LRU eviction correctness under high concurrency.
    pub fn check(&self, key: &str) -> RateLimitResult {
        let now = Instant::now();

        // Use entry API to update timestamp atomically with limiter access
        // This prevents race conditions where another request could access
        // the limiter between our get-or-create and timestamp update
        let old_timestamp = self.limiters.get(key).map(|e| e.last_access);
        let limiter = self
            .limiters
            .entry(key.to_string())
            .and_modify(|entry| {
                // Update timestamp for existing entries
                entry.last_access = now;
            })
            .or_insert_with(|| {
                let limiter = Arc::new(
                    GovernorRateLimiter::direct(self.default_quota)
                        .with_middleware::<StateInformationMiddleware>(),
                );
                RateLimitEntry {
                    limiter: limiter.clone(),
                    last_access: now,
                }
            })
            .limiter
            .clone();

        // Update access index for LRU eviction (write lock, brief)
        if let Ok(mut index) = self.access_index.write() {
            // Remove previous index entry for this key to prevent unbounded growth
            if let Some(ts) = old_timestamp
                && ts != now
            {
                let should_remove_bucket = if let Some(keys) = index.get_mut(&ts) {
                    keys.retain(|k| k != key);
                    keys.is_empty()
                } else {
                    false
                };
                if should_remove_bucket {
                    index.remove(&ts);
                }
            }
            let keys = index.entry(now).or_default();
            if !keys.iter().any(|k| k == key) {
                keys.push(key.to_string());
            }
        }

        // Try to consume a token from the rate limiter
        // With StateInformationMiddleware, check() returns StateSnapshot on success
        let result = limiter.check();

        match result {
            Ok(snapshot) => {
                // Get remaining capacity from Governor's state, capped to the
                // advertised rate limit to avoid reporting more than the limit
                let remaining = snapshot
                    .remaining_burst_capacity()
                    .min(self.requests_per_minute);

                let reset_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + self.window_seconds;

                RateLimitResult::Allowed {
                    limit: self.requests_per_minute,
                    remaining,
                    reset_at,
                }
            }
            Err(not_until) => {
                // Request denied - calculate when it will be allowed
                let clock = DefaultClock::default();
                let wait_duration = not_until.wait_time_from(clock.now());
                let retry_after = wait_duration.as_secs().max(1);

                // Calculate reset timestamp from Governor's actual wait time
                let reset_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + retry_after;

                RateLimitResult::Limited {
                    limit: self.requests_per_minute,
                    window_seconds: self.window_seconds,
                    retry_after,
                    reset_at,
                }
            }
        }
    }

    /// Cleanup expired entries (should be called periodically)
    ///
    /// Uses BTreeMap index for O(log n) LRU eviction:
    /// 1. Removes entries older than MAX_AGE_SECS
    /// 2. If still over limit, removes least recently used entries
    ///
    /// Complexity: O(m log n) where m is entries to remove, n is total entries
    /// This is significantly faster than O(n log n) sorting for large datasets.
    pub fn cleanup(&self) {
        const MAX_ENTRIES: usize = 10000;
        const MAX_AGE_SECS: u64 = 3600; // 1 hour

        // I1 fix: cleanup is now structured as two clearly-separated phases.
        //
        // The previous implementation swapped `*index` with a local map, then
        // iterated the *pre-swap* contents (holding entries already pruned by
        // the preceding `old_keys` loop) while modifying `*index` with a second
        // swap — causing the LRU eviction step to operate on stale data and
        // leaving state inconsistent under concurrent access.
        //
        // Phase 1 runs unconditionally (I2 fix) so stale entries are freed on
        // low-traffic servers regardless of total count. Phase 2 only runs
        // when the surviving set still exceeds the hard cap.
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(MAX_AGE_SECS);

        let Ok(mut index) = self.access_index.write() else {
            return;
        };

        // --- Phase 1: age-based pruning ---
        // The DashMap entry is the source of truth for the latest access time.
        // The BTreeMap index can contain older timestamps for the same key, so
        // never remove a live limiter solely because a stale index row aged out.
        let aged_keys: Vec<String> = self
            .limiters
            .iter()
            .filter(|entry| entry.last_access < cutoff)
            .map(|entry| entry.key().clone())
            .collect();

        for key in aged_keys {
            self.limiters.remove(&key);
        }

        // Rebuild the index from live limiter timestamps. This removes duplicate
        // stale rows and keeps the capacity-based LRU pass aligned with reality.
        Self::rebuild_access_index(&self.limiters, &mut index);

        // --- Phase 2: capacity-based LRU eviction ---
        if self.limiters.len() <= MAX_ENTRIES {
            return;
        }
        let target = MAX_ENTRIES / 2;
        let to_remove = self.limiters.len().saturating_sub(target);

        // Iterate the LIVE index from oldest to newest, collecting victims.
        let mut victims: Vec<String> = Vec::with_capacity(to_remove);
        'collect: for (_ts, keys) in index.iter() {
            for key in keys {
                victims.push(key.clone());
                if victims.len() >= to_remove {
                    break 'collect;
                }
            }
        }

        for key in &victims {
            self.limiters.remove(key);
        }

        // Rebuild the index without evicted keys. We can't mutate values
        // during the iteration above, so we do a single filter pass now.
        let victims_set: std::collections::HashSet<String> = victims.iter().cloned().collect();
        for (_ts, keys) in index.iter_mut() {
            keys.retain(|k| !victims_set.contains(k));
        }
        index.retain(|_, keys| !keys.is_empty());

        tracing::info!(
            "Rate limiter LRU cleanup: removed {} oldest entries, {} remaining",
            victims.len(),
            self.limiters.len()
        );
    }

    fn rebuild_access_index(
        limiters: &DashMap<String, RateLimitEntry>,
        index: &mut BTreeMap<Instant, Vec<String>>,
    ) {
        index.clear();
        for entry in limiters.iter() {
            index
                .entry(entry.last_access)
                .or_default()
                .push(entry.key().clone());
        }
    }
}

/// Result of a rate limit check
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        limit: u32,
        remaining: u32,
        reset_at: u64,
    },
    /// Request is rate limited
    Limited {
        limit: u32,
        window_seconds: u64,
        retry_after: u64,
        reset_at: u64,
    },
}

/// Rate limiting middleware function
pub async fn rate_limit(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    // Skip rate limiting for health and docs endpoints
    let path = req.uri().path();
    if path == "/api/v1/health"
        || path == "/health"
        || path.starts_with("/api/docs")
        || path.starts_with("/swagger")
    {
        return Ok(next.run(req).await);
    }

    // Get authentication info from request extensions
    let auth_ext = req.extensions().get::<AuthExtension>().cloned();

    if let Some(auth) = auth_ext {
        // Check if user is Admin - admins bypass rate limiting
        if auth.permission == Permission::Admin {
            tracing::debug!(
                "Admin key {} - bypassing rate limit",
                mask_key(&auth.api_key)
            );
            return Ok(next.run(req).await);
        }

        // Check rate limit for this API key
        match state.rate_limiter.check(&auth.api_key) {
            RateLimitResult::Allowed {
                limit,
                remaining,
                reset_at,
            } => {
                tracing::debug!(
                    "Rate limit check passed for key {}: {}/{} remaining",
                    mask_key(&auth.api_key),
                    remaining,
                    limit
                );

                // Run the request and add rate limit headers to response
                let mut response = next.run(req).await;
                let headers = response.headers_mut();

                // Insert rate limit headers - these should always be valid ASCII
                if let Ok(header_val) = HeaderValue::from_str(&limit.to_string()) {
                    headers.insert("X-RateLimit-Limit", header_val);
                }
                if let Ok(header_val) = HeaderValue::from_str(&remaining.to_string()) {
                    headers.insert("X-RateLimit-Remaining", header_val);
                }
                if let Ok(header_val) = HeaderValue::from_str(&reset_at.to_string()) {
                    headers.insert("X-RateLimit-Reset", header_val);
                }

                Ok(response)
            }
            RateLimitResult::Limited {
                limit,
                window_seconds,
                retry_after,
                reset_at,
            } => {
                tracing::warn!(
                    "Rate limit exceeded for key {}: limit={}, retry_after={}s",
                    mask_key(&auth.api_key),
                    limit,
                    retry_after
                );

                // Create error response
                let error_body = RateLimitErrorResponse {
                    error: "Rate limit exceeded".to_string(),
                    limit,
                    window_seconds,
                    retry_after,
                };

                // Build response with proper headers
                let json_body = serde_json::to_string(&error_body)
                    .unwrap_or_else(|_| r#"{"error":"Rate limit exceeded"}"#.to_string());

                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Content-Type", "application/json")
                    .header("X-RateLimit-Limit", limit.to_string())
                    .header("X-RateLimit-Remaining", "0")
                    .header("X-RateLimit-Reset", reset_at.to_string())
                    .header("Retry-After", retry_after.to_string())
                    .body(Body::from(json_body))
                    .unwrap_or_else(|_| {
                        // Fallback if response building fails
                        Response::builder()
                            .status(StatusCode::TOO_MANY_REQUESTS)
                            .body(Body::from(r#"{"error":"Rate limit exceeded"}"#))
                            .expect("Fallback response should always build")
                    });

                Err(response)
            }
        }
    } else {
        // No authentication - this shouldn't happen as auth middleware runs first
        // But if it does, allow the request to proceed (will fail at auth check)
        tracing::warn!("Rate limit middleware: No auth extension found in request");
        Ok(next.run(req).await)
    }
}

impl Clone for PerKeyRateLimiter {
    fn clone(&self) -> Self {
        Self {
            limiters: self.limiters.clone(),
            access_index: self.access_index.clone(),
            default_quota: self.default_quota,
            requests_per_minute: self.requests_per_minute,
            window_seconds: self.window_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_first_request() {
        let limiter = PerKeyRateLimiter::new(100);
        match limiter.check("key") {
            RateLimitResult::Allowed { limit, .. } => {
                assert_eq!(limit, 100);
            }
            RateLimitResult::Limited { .. } => panic!("expected allowed"),
        }
    }

    #[test]
    fn test_rate_limiter_zero_defaults() {
        let limiter = PerKeyRateLimiter::new(0);
        match limiter.check("key") {
            RateLimitResult::Allowed { limit, .. } => {
                assert_eq!(limit, 100);
            }
            RateLimitResult::Limited { .. } => panic!("expected allowed"),
        }
    }

    /// I1/I2 regression: cleanup() is idempotent and leaves the live index
    /// consistent with the DashMap after a run. Repeated invocations on a
    /// small set of keys must not corrupt state or remove live entries.
    #[test]
    fn test_rate_limiter_cleanup_is_idempotent_under_cap() {
        let limiter = PerKeyRateLimiter::new(100);
        for i in 0..50 {
            let key = format!("key{}", i);
            let _ = limiter.check(&key);
        }
        let before = limiter.limiters.len();
        limiter.cleanup();
        limiter.cleanup();
        // All entries are fresh (just created) so none should be aged out.
        assert_eq!(limiter.limiters.len(), before);
        // Index shouldn't have orphaned entries for keys we removed.
        let index = limiter.access_index.read().expect("lock");
        let index_key_count: usize = index.values().map(|v| v.len()).sum();
        assert!(
            index_key_count >= before,
            "index must reference every live limiter; got {} entries in index, {} live",
            index_key_count,
            before
        );
    }

    #[test]
    fn test_rate_limiter_cleanup_keeps_recent_key_with_stale_index_row() {
        let limiter = PerKeyRateLimiter::new(100);
        let key = "recent-key";
        let _ = limiter.check(key);

        let fresh_access = Instant::now();
        if let Some(mut entry) = limiter.limiters.get_mut(key) {
            entry.last_access = fresh_access;
        }

        {
            let mut index = limiter.access_index.write().expect("lock");
            index.clear();
            index.insert(
                fresh_access - std::time::Duration::from_secs(7200),
                vec![key.to_string()],
            );
            index.insert(fresh_access, vec![key.to_string()]);
        }

        limiter.cleanup();

        assert!(
            limiter.limiters.contains_key(key),
            "cleanup must not remove a key whose live last_access is fresh"
        );

        let index = limiter.access_index.read().expect("lock");
        let indexed_count: usize = index
            .values()
            .map(|keys| keys.iter().filter(|k| *k == key).count())
            .sum();
        assert_eq!(indexed_count, 1, "cleanup should collapse stale index rows");
    }
}
