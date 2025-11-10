// Rate Limiting Middleware

use crate::api::{
    config::Permission,
    middleware::auth::AuthExtension,
    models::error::RateLimitErrorResponse,
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
    clock::{Clock, DefaultClock},
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Per-key rate limiter storage
pub struct PerKeyRateLimiter {
    /// Storage for per-key rate limiters
    limiters: Arc<DashMap<String, Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
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
        let default_quota = Quota::per_minute(
            NonZeroU32::new(requests_per_minute).unwrap_or(NonZeroU32::new(100).unwrap()),
        );

        Self {
            limiters: Arc::new(DashMap::new()),
            default_quota,
            requests_per_minute,
            window_seconds: 60,
        }
    }

    /// Get or create a rate limiter for a specific API key
    fn get_or_create_limiter(&self, key: &str) -> Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        if let Some(limiter) = self.limiters.get(key) {
            return limiter.clone();
        }

        // Create new limiter for this key
        let limiter = Arc::new(GovernorRateLimiter::direct(self.default_quota));
        self.limiters.insert(key.to_string(), limiter.clone());
        limiter
    }

    /// Check rate limit for a specific key and return rate limit info
    pub fn check(&self, key: &str) -> RateLimitResult {
        let limiter = self.get_or_create_limiter(key);

        // Try to consume a token from the rate limiter
        let snapshot = limiter.check();

        match snapshot {
            Ok(_) => {
                // Request allowed
                // Calculate remaining capacity (approximation since governor doesn't expose it directly)
                // We do this by checking how many more requests would succeed
                let mut remaining = 0u32;
                for _ in 0..self.requests_per_minute {
                    match limiter.check() {
                        Ok(_) => remaining += 1,
                        Err(_) => break,
                    }
                }

                // Calculate reset time - use system time since QuantaInstant isn't directly convertible
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let reset_at = now + self.window_seconds;

                RateLimitResult::Allowed {
                    limit: self.requests_per_minute,
                    remaining,
                    reset_at,
                }
            }
            Err(not_until) => {
                // Request denied - calculate when it will be allowed
                let wait_duration = not_until.wait_time_from(DefaultClock::default().now());
                let retry_after = wait_duration.as_secs().max(1);

                // Calculate reset timestamp
                let reset_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + retry_after;

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
    pub fn cleanup(&self) {
        // Remove entries if map grows too large
        if self.limiters.len() > 10000 {
            // Clear oldest half
            let keys_to_remove: Vec<String> = self.limiters
                .iter()
                .take(self.limiters.len() / 2)
                .map(|entry| entry.key().clone())
                .collect();

            for key in keys_to_remove {
                self.limiters.remove(&key);
            }

            tracing::info!("Rate limiter cleanup: removed {} entries", self.limiters.len() / 2);
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
    if path == "/api/v1/health" || path == "/health" || path.starts_with("/api/docs") || path.starts_with("/swagger") {
        return Ok(next.run(req).await);
    }

    // Get authentication info from request extensions
    let auth_ext = req.extensions().get::<AuthExtension>().cloned();

    if let Some(auth) = auth_ext {
        // Check if user is Admin - admins bypass rate limiting
        if auth.permission == Permission::Admin {
            tracing::debug!("Admin key {} - bypassing rate limit", auth.api_key);
            return Ok(next.run(req).await);
        }

        // Check rate limit for this API key
        match state.rate_limiter.check(&auth.api_key) {
            RateLimitResult::Allowed { limit, remaining, reset_at } => {
                tracing::debug!(
                    "Rate limit check passed for key {}: {}/{} remaining",
                    auth.api_key,
                    remaining,
                    limit
                );

                // Run the request and add rate limit headers to response
                let mut response = next.run(req).await;
                let headers = response.headers_mut();

                headers.insert(
                    "X-RateLimit-Limit",
                    HeaderValue::from_str(&limit.to_string()).unwrap(),
                );
                headers.insert(
                    "X-RateLimit-Remaining",
                    HeaderValue::from_str(&remaining.to_string()).unwrap(),
                );
                headers.insert(
                    "X-RateLimit-Reset",
                    HeaderValue::from_str(&reset_at.to_string()).unwrap(),
                );

                Ok(response)
            }
            RateLimitResult::Limited { limit, window_seconds, retry_after, reset_at } => {
                tracing::warn!(
                    "Rate limit exceeded for key {}: limit={}, retry_after={}s",
                    auth.api_key,
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
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Content-Type", "application/json")
                    .header("X-RateLimit-Limit", limit.to_string())
                    .header("X-RateLimit-Remaining", "0")
                    .header("X-RateLimit-Reset", reset_at.to_string())
                    .header("Retry-After", retry_after.to_string())
                    .body(Body::from(serde_json::to_string(&error_body).unwrap()))
                    .unwrap();

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
            default_quota: self.default_quota,
            requests_per_minute: self.requests_per_minute,
            window_seconds: self.window_seconds,
        }
    }
}
