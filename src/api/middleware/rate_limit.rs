// Rate Limiting Middleware

use crate::api::models::error::ApiError;
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Rate limiter wrapper
pub struct RateLimitLayer {
    limiter: Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl RateLimitLayer {
    /// Create new rate limiter
    pub fn new(requests_per_minute: u32) -> Self {
        let quota = Quota::per_minute(
            NonZeroU32::new(requests_per_minute).unwrap_or(NonZeroU32::new(100).unwrap()),
        );
        let limiter = Arc::new(GovernorRateLimiter::direct(quota));

        Self { limiter }
    }

    /// Get the limiter
    pub fn limiter(&self) -> Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        self.limiter.clone()
    }
}

impl Clone for RateLimitLayer {
    fn clone(&self) -> Self {
        Self {
            limiter: self.limiter.clone(),
        }
    }
}

/// Rate limiting middleware function
pub async fn rate_limit(req: Request, next: Next) -> Result<Response, ApiError> {
    // For now, use a global rate limiter
    // In production, you'd want per-API-key rate limiting
    // This is simplified to avoid complex state management

    // Extract API key for logging purposes
    let api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("anonymous");

    // TODO: Implement per-key rate limiting with a HashMap<String, RateLimiter>
    // For now, we'll allow all requests through but log the key
    tracing::debug!("Rate limit check for key: {}", api_key);

    Ok(next.run(req).await)
}

/// Global rate limiter for per-key tracking
pub struct PerKeyRateLimiter {
    limiters: Arc<tokio::sync::RwLock<std::collections::HashMap<String, Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>>,
    default_quota: Quota,
}

impl PerKeyRateLimiter {
    /// Create new per-key rate limiter
    pub fn new(requests_per_minute: u32) -> Self {
        let default_quota = Quota::per_minute(
            NonZeroU32::new(requests_per_minute).unwrap_or(NonZeroU32::new(100).unwrap()),
        );

        Self {
            limiters: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            default_quota,
        }
    }

    /// Check rate limit for a specific key
    pub async fn check(&self, key: &str) -> Result<(), ApiError> {
        // Get or create limiter for this key
        let limiter = {
            let mut limiters = self.limiters.write().await;
            limiters
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(GovernorRateLimiter::direct(self.default_quota)))
                .clone()
        };

        // Check rate limit
        match limiter.check() {
            Ok(_) => Ok(()),
            Err(_) => Err(ApiError::RateLimited(format!(
                "Rate limit exceeded for key. Maximum {} requests per minute allowed.",
                self.default_quota.burst_size().get()
            ))),
        }
    }

    /// Cleanup old entries periodically
    pub async fn cleanup_old_entries(&self) {
        let mut limiters = self.limiters.write().await;

        // Remove entries that haven't been used recently
        // This is a simple implementation - in production you'd want more sophisticated cleanup
        if limiters.len() > 1000 {
            limiters.clear();
            tracing::info!("Cleaned up rate limiter cache");
        }
    }
}

impl Clone for PerKeyRateLimiter {
    fn clone(&self) -> Self {
        Self {
            limiters: self.limiters.clone(),
            default_quota: self.default_quota,
        }
    }
}
