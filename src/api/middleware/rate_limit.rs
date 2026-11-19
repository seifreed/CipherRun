// Rate Limiting Middleware

use crate::api::{
    config::Permission,
    middleware::auth::{AuthExtension, is_stream_path},
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
    Quota, RateLimiter as GovernorRateLimiter,
    clock::{Clock, DefaultClock},
    middleware::StateInformationMiddleware,
    state::{InMemoryState, NotKeyed},
};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

/// Type alias for the governor rate limiter with state information middleware
/// This allows us to get remaining capacity information after each check
type Limiter =
    Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock, StateInformationMiddleware>>;

/// Fallback requests-per-minute used when a caller supplies an invalid (zero) limit.
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 100;

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
    cleanup_failure_reported: Arc<AtomicBool>,
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
        // Ensure we have a valid non-zero value, defaulting to a sane rate if invalid
        let rpm = NonZeroU32::new(requests_per_minute)
            .or(NonZeroU32::new(DEFAULT_RATE_LIMIT_PER_MINUTE))
            .unwrap_or(NonZeroU32::MIN);
        let default_quota = Quota::per_minute(rpm);
        // Store the actual RPM value used (may differ from input if input was 0)
        let effective_rpm = rpm.get();

        Self {
            limiters: Arc::new(DashMap::new()),
            access_index: Arc::new(RwLock::new(BTreeMap::new())),
            cleanup_failure_reported: Arc::new(AtomicBool::new(false)),
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

        let mut index = match self.access_index.write() {
            Ok(index) => {
                self.cleanup_failure_reported
                    .store(false, Ordering::Relaxed);
                index
            }
            Err(_) => {
                if !self.cleanup_failure_reported.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        event_name = "api.rate_limit.cleanup_failed",
                        operation = "cleanup",
                        error_type = "lock_poisoned",
                        error_code = "access_index_unavailable",
                        outcome = "skipped",
                        "Rate limit entry cleanup skipped"
                    );
                }
                return;
            }
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
        'collect: for keys in index.values() {
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
        for keys in index.values_mut() {
            keys.retain(|k| !victims_set.contains(k));
        }
        index.retain(|_, keys| !keys.is_empty());

        tracing::info!(
            event_name = "api.rate_limit.entries_evicted",
            removed = victims.len(),
            remaining = self.limiters.len(),
            "Rate limiter LRU cleanup completed"
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

fn quota_scope(auth: &AuthExtension) -> String {
    auth.tenant_id
        .as_deref()
        .map(|tenant| format!("tenant:{tenant}"))
        .unwrap_or_else(|| format!("key:{}", auth.key_id))
}

fn quota_scope_type(auth: &AuthExtension) -> &'static str {
    if auth.tenant_id.is_some() {
        "tenant"
    } else {
        "credential"
    }
}

fn log_rate_limit_result(scope_type: &str, result: &RateLimitResult) {
    match result {
        RateLimitResult::Allowed {
            limit, remaining, ..
        } => tracing::debug!(
            event_name = "api.rate_limit.allowed",
            quota_scope_type = scope_type,
            limit,
            remaining,
            "Rate limit check passed"
        ),
        RateLimitResult::Limited {
            limit, retry_after, ..
        } => tracing::warn!(
            event_name = "api.rate_limit.exceeded",
            quota_scope_type = scope_type,
            limit,
            retry_after_seconds = retry_after,
            "Rate limit exceeded"
        ),
    }
}

/// Rate limiting middleware function
#[allow(clippy::result_large_err)]
pub async fn rate_limit(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    // Skip rate limiting for health and docs endpoints
    let path = req.uri().path();
    if path == "/api/v1/health"
        || path == "/health"
        || path == "/api/docs"
        || path.starts_with("/api/docs/")
        || path == "/swagger"
        || path.starts_with("/swagger/")
    {
        return Ok(next.run(req).await);
    }

    // Get authentication info from request extensions
    let auth_ext = req.extensions().get::<AuthExtension>().cloned();

    if let Some(auth) = auth_ext {
        // Check if user is Admin - admins bypass rate limiting
        if auth.permission == Permission::Admin {
            tracing::debug!(
                event_name = "api.rate_limit.admin_bypass",
                "Administrator credential bypassed rate limiting"
            );
            return Ok(next.run(req).await);
        }

        // Tenant credentials share one quota; unscoped credentials retain a
        // per-key quota so one tenant cannot consume another tenant's budget.
        let scope = quota_scope(&auth);
        let result = state.rate_limiter.check(&scope);
        log_rate_limit_result(quota_scope_type(&auth), &result);
        match result {
            RateLimitResult::Allowed {
                limit,
                remaining,
                reset_at,
            } => {
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
                        // Fallback if response building fails. Response::new is
                        // infallible (no builder), so this cannot panic.
                        let mut resp =
                            Response::new(Body::from(r#"{"error":"Rate limit exceeded"}"#));
                        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                        resp
                    });

                Err(response)
            }
        }
    } else if is_stream_path(req.uri().path()) {
        tracing::debug!(
            event_name = "api.rate_limit.stream_ticket",
            "One-use stream ticket request bypassed per-key rate limiting"
        );
        Ok(next.run(req).await)
    } else {
        // No authentication - this shouldn't happen as auth middleware runs first
        // except for one-use stream tickets.
        tracing::warn!(
            event_name = "api.rate_limit.auth_missing",
            "Rate limit middleware has no auth extension"
        );
        Ok(next.run(req).await)
    }
}

impl Clone for PerKeyRateLimiter {
    fn clone(&self) -> Self {
        Self {
            limiters: self.limiters.clone(),
            access_index: self.access_index.clone(),
            cleanup_failure_reported: self.cleanup_failure_reported.clone(),
            default_quota: self.default_quota,
            requests_per_minute: self.requests_per_minute,
            window_seconds: self.window_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiConfig;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use std::io::Write;
    use std::sync::Mutex;
    use tower::ServiceExt;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedOutputWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedOutputWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedOutputWriter(self.0.clone())
        }
    }

    impl Write for CapturedOutputWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tenant_credentials_share_quota_scope() {
        let auth = AuthExtension {
            permission: Permission::User,
            key_id: "key-1".to_string(),
            principal_id: "principal-1".to_string(),
            tenant_id: Some("tenant-1".to_string()),
        };
        assert_eq!(quota_scope(&auth), "tenant:tenant-1");

        let mut unscoped = auth;
        unscoped.tenant_id = None;
        assert_eq!(quota_scope(&unscoped), "key:key-1");
    }

    #[test]
    fn rate_limit_logs_scope_type_without_credentials_or_tenant_ids() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(output.clone())
            .finish();
        let tenant_auth = AuthExtension {
            permission: Permission::User,
            key_id: "secret-key-id".to_string(),
            principal_id: "secret-principal-id".to_string(),
            tenant_id: Some("secret-tenant-id".to_string()),
        };
        let credential_auth = AuthExtension {
            tenant_id: None,
            ..tenant_auth.clone()
        };

        tracing::subscriber::with_default(subscriber, || {
            log_rate_limit_result(
                quota_scope_type(&tenant_auth),
                &RateLimitResult::Allowed {
                    limit: 100,
                    remaining: 99,
                    reset_at: 1,
                },
            );
            log_rate_limit_result(
                quota_scope_type(&credential_auth),
                &RateLimitResult::Limited {
                    limit: 100,
                    window_seconds: 60,
                    retry_after: 1,
                    reset_at: 1,
                },
            );
        });

        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("api.rate_limit.allowed"));
        assert!(logs.contains("api.rate_limit.exceeded"));
        assert!(logs.contains("quota_scope_type=\"tenant\""));
        assert!(logs.contains("quota_scope_type=\"credential\""));
        assert!(!logs.contains("secret-key-id"));
        assert!(!logs.contains("secret-principal-id"));
        assert!(!logs.contains("secret-tenant-id"));
    }

    #[test]
    fn stream_ticket_bypass_is_debug_logged_without_ticket_data() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(output.clone())
            .finish();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime should build");

        let response = tracing::subscriber::with_default(subscriber, || {
            runtime.block_on(async {
                let state = Arc::new(AppState::new(ApiConfig::default()).unwrap());
                let app = Router::new()
                    .route("/api/v1/scan/{id}/stream", get(|| async { StatusCode::OK }))
                    .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
                    .with_state(state);

                app.oneshot(
                    Request::builder()
                        .uri("/api/v1/scan/scan-id/stream?ticket=secret-ticket")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            })
        });

        assert_eq!(response.status(), StatusCode::OK);
        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("api.rate_limit.stream_ticket"), "{logs}");
        assert!(logs.contains("DEBUG"), "{logs}");
        assert!(!logs.contains("secret-ticket"), "{logs}");
        assert!(!logs.contains("api.rate_limit.auth_missing"), "{logs}");
    }

    #[tokio::test]
    async fn middleware_adds_limit_headers_rejects_excess_and_honors_bypasses() {
        let config = ApiConfig {
            rate_limit_per_minute: 1,
            ..ApiConfig::default()
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let app = Router::new()
            .route("/protected", get(|| async { StatusCode::NO_CONTENT }))
            .route("/api/v1/health", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
            .with_state(state);

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let mut user_request = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        user_request.extensions_mut().insert(AuthExtension {
            permission: Permission::User,
            key_id: "user-key".to_string(),
            principal_id: "user".to_string(),
            tenant_id: None,
        });
        let allowed = app.clone().oneshot(user_request).await.unwrap();
        assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
        assert_eq!(allowed.headers()["X-RateLimit-Limit"], "1");
        assert_eq!(allowed.headers()["X-RateLimit-Remaining"], "0");
        assert!(allowed.headers().contains_key("X-RateLimit-Reset"));

        let mut limited_request = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        limited_request.extensions_mut().insert(AuthExtension {
            permission: Permission::User,
            key_id: "user-key".to_string(),
            principal_id: "user".to_string(),
            tenant_id: None,
        });
        let limited = app.clone().oneshot(limited_request).await.unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers()["X-RateLimit-Remaining"], "0");
        assert!(limited.headers().contains_key("Retry-After"));

        let mut admin_request = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        admin_request.extensions_mut().insert(AuthExtension {
            permission: Permission::Admin,
            key_id: "admin-key".to_string(),
            principal_id: "admin".to_string(),
            tenant_id: None,
        });
        let admin = app.clone().oneshot(admin_request).await.unwrap();
        assert_eq!(admin.status(), StatusCode::NO_CONTENT);
        assert!(!admin.headers().contains_key("X-RateLimit-Limit"));

        let unauthenticated = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn cleanup_logs_poisoned_index_without_sensitive_context() {
        let limiter = PerKeyRateLimiter::new(100);
        let index = limiter.access_index.clone();
        let _ = std::thread::spawn(move || {
            let _guard = index.write().unwrap();
            panic!("test-only lock poison");
        })
        .join();

        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            limiter.cleanup();
            limiter.cleanup();
        });

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert_eq!(output.matches("api.rate_limit.cleanup_failed").count(), 1);
        assert!(output.contains("access_index_unavailable"), "{output}");
        assert!(!output.contains("test-only lock poison"), "{output}");
    }

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
    fn cleanup_removes_expired_entries_then_evicts_oldest_when_over_cap() {
        let limiter = PerKeyRateLimiter::new(100);
        for index in 0..10_001 {
            let _ = limiter.check(&format!("fresh-{index}"));
        }
        let expired_key = "expired";
        let _ = limiter.check(expired_key);
        if let Some(mut entry) = limiter.limiters.get_mut(expired_key) {
            entry.last_access = Instant::now() - std::time::Duration::from_secs(7200);
        }

        limiter.cleanup();

        assert_eq!(limiter.limiters.len(), 5_000);
        assert!(!limiter.limiters.contains_key(expired_key));
        assert!(!limiter.limiters.contains_key("fresh-0"));
        assert!(limiter.limiters.contains_key("fresh-10000"));
        let index = limiter.access_index.read().expect("lock");
        let indexed_count: usize = index.values().map(Vec::len).sum();
        assert_eq!(indexed_count, limiter.limiters.len());
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
