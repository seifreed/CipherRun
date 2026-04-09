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
    if key.len() > 8 {
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    } else if key.len() > 4 {
        format!("{}****", &key[..4])
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
            index.entry(now).or_default().push(key.to_string());
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

        if self.limiters.len() <= MAX_ENTRIES {
            return;
        }

        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(MAX_AGE_SECS);

        // Use BTreeMap for efficient range query - O(log n) to find old entries
        if let Ok(mut index) = self.access_index.write() {
            // Collect keys to remove from old timestamps
            let old_keys: Vec<String> = index
                .range(..cutoff)
                .flat_map(|(_, keys)| keys.clone())
                .collect();

            // Remove old entries from DashMap - O(m log n)
            for key in old_keys {
                self.limiters.remove(&key);
            }

            // Clear old entries from index - O(log n) to split
            let mut remaining = BTreeMap::new();
            std::mem::swap(&mut *index, &mut remaining);
            *index = remaining.split_off(&cutoff);

            // If still over limit, remove oldest entries using BTreeMap
            if self.limiters.len() > MAX_ENTRIES {
                let to_remove = self.limiters.len() - MAX_ENTRIES / 2;
                let mut removed = 0;

                // BTreeMap is sorted by timestamp, iterate from oldest
                for (_timestamp, keys) in remaining.iter() {
                    for key in keys {
                        if removed >= to_remove {
                            break;
                        }
                        self.limiters.remove(key);
                        removed += 1;
                    }
                    if removed >= to_remove {
                        break;
                    }
                }

                // Remove evicted entries from index
                let evicted_cutoff = *remaining.keys().next().unwrap_or(&cutoff);
                let mut new_index = BTreeMap::new();
                std::mem::swap(&mut *index, &mut new_index);
                *index = new_index.split_off(&evicted_cutoff);

                tracing::info!(
                    "Rate limiter LRU cleanup: removed {} oldest entries, {} remaining",
                    removed,
                    self.limiters.len()
                );
            }
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
}
