// CT Log API Client
//
// Handles HTTP communication with CT log servers

use super::Result;
use crate::error::TlsError;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

/// Maximum number of retries for network failures
const MAX_RETRIES: u32 = 3;

/// Initial backoff duration (doubled with each retry)
const INITIAL_BACKOFF_MS: u64 = 100;

/// Maximum backoff duration
const MAX_BACKOFF_MS: u64 = 5000;

/// CT Log API Client
pub struct CtClient {
    client: reqwest::Client,
}

impl CtClient {
    /// Create a new CT Log API client
    ///
    /// Returns a CtClient instance with default timeout settings.
    /// The HTTP client is configured with:
    /// - 30 second timeout
    /// - Connection pool with 10 max idle connections per host
    ///
    /// Note: If the HTTP client fails to build (extremely rare),
    /// a default client without timeout settings will be used.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to build HTTP client with timeout settings: {}. Using default client.",
                    e
                );
                reqwest::Client::new()
            });

        Self { client }
    }

    /// Get the current tree size (STH - Signed Tree Head)
    pub async fn get_tree_size(&self, log_url: &str) -> Result<u64> {
        let url = format!("{}/ct/v1/get-sth", log_url.trim_end_matches('/'));

        let response = self
            .retry_request(|| async { self.client.get(&url).send().await })
            .await?;

        // Validate response size to prevent memory exhaustion
        let content_length = response.content_length();
        if let Some(len) = content_length {
            const MAX_RESPONSE_SIZE: u64 = 1024 * 1024; // 1 MB max for STH response
            if len > MAX_RESPONSE_SIZE {
                return Err(TlsError::ParseError {
                    message: format!(
                        "STH response too large: {} bytes (max {})",
                        len, MAX_RESPONSE_SIZE
                    ),
                });
            }
        }

        let sth: SignedTreeHead = response.json().await.map_err(|e| TlsError::ParseError {
            message: format!("Failed to parse STH response: {}", e),
        })?;

        Ok(sth.tree_size)
    }

    /// Get entries from the CT log
    pub async fn get_entries(
        &self,
        log_url: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<CtLogEntryResponse>> {
        // Validate range
        if start > end {
            return Err(TlsError::ParseError {
                message: format!("Invalid range: start ({}) > end ({})", start, end),
            });
        }

        let url = format!(
            "{}/ct/v1/get-entries?start={}&end={}",
            log_url.trim_end_matches('/'),
            start,
            end
        );

        debug!("Fetching entries from {} to {}", start, end);

        let mut response = self
            .retry_request(|| async { self.client.get(&url).send().await })
            .await?;

        // Validate response size to prevent memory exhaustion
        // Check Content-Length if present, but also limit the actual bytes read
        // since chunked responses may not have Content-Length
        const MAX_ENTRIES_RESPONSE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB
        if let Some(len) = response.content_length()
            && len > MAX_ENTRIES_RESPONSE_SIZE
        {
            return Err(TlsError::ParseError {
                message: format!(
                    "Entries response too large: {} bytes (max {})",
                    len, MAX_ENTRIES_RESPONSE_SIZE
                ),
            });
        }

        // Read the body in chunks to enforce size limit even for chunked responses
        // that bypass Content-Length checks. This prevents memory exhaustion from
        // malicious servers sending unbounded data without Content-Length.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| TlsError::ParseError {
            message: format!("Failed to read entries response body: {}", e),
        })? {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > MAX_ENTRIES_RESPONSE_SIZE {
                return Err(TlsError::ParseError {
                    message: format!(
                        "Entries response body too large: >{} bytes (max {})",
                        body.len(),
                        MAX_ENTRIES_RESPONSE_SIZE
                    ),
                });
            }
        }
        let bytes = bytes::Bytes::from(body);

        let entries_response: EntriesResponse =
            serde_json::from_slice(&bytes).map_err(|e| TlsError::ParseError {
                message: format!("Failed to parse entries response: {}", e),
            })?;

        Ok(entries_response.entries)
    }

    /// Retry a request with exponential backoff
    async fn retry_request<F, Fut>(&self, request_fn: F) -> Result<reqwest::Response>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<reqwest::Response, reqwest::Error>>,
    {
        let mut backoff = Duration::from_millis(INITIAL_BACKOFF_MS);
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            match request_fn().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(response);
                    } else if response.status() == 429 {
                        // Rate limited - wait and retry
                        warn!(
                            "Rate limited (429), retrying after {:?} (attempt {}/{})",
                            backoff,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, Duration::from_millis(MAX_BACKOFF_MS));
                        last_error = Some(format!("Rate limited: {}", response.status()));
                        continue;
                    } else if response.status().is_server_error() {
                        // Server error - retry
                        warn!(
                            "Server error ({}), retrying after {:?} (attempt {}/{})",
                            response.status(),
                            backoff,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, Duration::from_millis(MAX_BACKOFF_MS));
                        last_error = Some(format!("Server error: {}", response.status()));
                        continue;
                    } else {
                        // Client error - don't retry
                        return Err(TlsError::HttpError {
                            status: response.status().as_u16(),
                            details: format!("Request failed with status: {}", response.status()),
                        });
                    }
                }
                Err(e) => {
                    if attempt < MAX_RETRIES - 1 {
                        warn!(
                            "Network error: {}, retrying after {:?} (attempt {}/{})",
                            e,
                            backoff,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, Duration::from_millis(MAX_BACKOFF_MS));
                        last_error = Some(format!("Network error: {}", e));
                    } else {
                        return Err(TlsError::Other(format!("Request failed: {}", e)));
                    }
                }
            }
        }

        Err(TlsError::Other(format!(
            "Request failed after {} retries: {}",
            MAX_RETRIES,
            last_error.unwrap_or_else(|| "Unknown error".to_string())
        )))
    }
}

impl Default for CtClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Signed Tree Head response
#[derive(Debug, Deserialize, Serialize)]
struct SignedTreeHead {
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,
    tree_head_signature: String,
}

/// Get-entries API response
#[derive(Debug, Deserialize, Serialize)]
struct EntriesResponse {
    entries: Vec<CtLogEntryResponse>,
}

/// Individual CT log entry from API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CtLogEntryResponse {
    pub leaf_input: String,
    pub extra_data: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get,
    };
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    #[test]
    fn test_client_creation() {
        let client = CtClient::new();
        assert!(std::ptr::addr_of!(client.client) as usize != 0);
    }

    #[derive(Clone)]
    struct TestState {
        sth_calls: Arc<AtomicUsize>,
        entries_calls: Arc<AtomicUsize>,
        fail_parse: Arc<AtomicUsize>,
    }

    async fn start_test_server(state: TestState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/ct/v1/get-sth",
                get(|State(state): State<TestState>| async move {
                    let call = state.sth_calls.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
                    }
                    (
                        StatusCode::OK,
                        Json(json!({
                            "tree_size": 7,
                            "timestamp": 0,
                            "sha256_root_hash": "root",
                            "tree_head_signature": "sig"
                        })),
                    )
                        .into_response()
                }),
            )
            .route(
                "/ct/v1/get-entries",
                get(|State(state): State<TestState>| async move {
                    let call = state.entries_calls.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    let fail_parse = state.fail_parse.load(Ordering::SeqCst) > 0;
                    if fail_parse {
                        return (StatusCode::OK, "not-json").into_response();
                    }
                    (
                        StatusCode::OK,
                        Json(json!({
                            "entries": [
                                {"leaf_input": "a", "extra_data": "b"},
                                {"leaf_input": "c", "extra_data": "d"}
                            ]
                        })),
                    )
                        .into_response()
                }),
            )
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn test_get_tree_size_retries_on_429() {
        let state = TestState {
            sth_calls: Arc::new(AtomicUsize::new(0)),
            entries_calls: Arc::new(AtomicUsize::new(0)),
            fail_parse: Arc::new(AtomicUsize::new(0)),
        };
        let (addr, _handle) = start_test_server(state).await;

        let client = CtClient::new();
        let base = format!("http://{}", addr);
        let size = client.get_tree_size(&base).await.unwrap();
        assert_eq!(size, 7);
    }

    #[tokio::test]
    async fn test_get_entries_retries_on_500() {
        let state = TestState {
            sth_calls: Arc::new(AtomicUsize::new(0)),
            entries_calls: Arc::new(AtomicUsize::new(0)),
            fail_parse: Arc::new(AtomicUsize::new(0)),
        };
        let (addr, _handle) = start_test_server(state).await;

        let client = CtClient::new();
        let base = format!("http://{}", addr);
        let entries = client.get_entries(&base, 0, 1).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].leaf_input, "a");
    }

    #[tokio::test]
    async fn test_get_tree_size_client_error() {
        let state = TestState {
            sth_calls: Arc::new(AtomicUsize::new(0)),
            entries_calls: Arc::new(AtomicUsize::new(0)),
            fail_parse: Arc::new(AtomicUsize::new(0)),
        };
        let (addr, _handle) = start_test_server(state).await;

        let client = CtClient::new();
        let bad = format!("http://{}/bad-path", addr);
        let err = client.get_tree_size(&bad).await.unwrap_err();
        assert!(format!("{err}").contains("status"));
    }

    #[tokio::test]
    async fn test_get_entries_parse_error() {
        let state = TestState {
            sth_calls: Arc::new(AtomicUsize::new(0)),
            entries_calls: Arc::new(AtomicUsize::new(0)),
            fail_parse: Arc::new(AtomicUsize::new(1)),
        };
        let (addr, _handle) = start_test_server(state).await;

        let client = CtClient::new();
        let base = format!("http://{}", addr);
        let err = client.get_entries(&base, 0, 0).await.unwrap_err();
        assert!(format!("{err}").contains("Failed to parse entries response"));
    }

    #[tokio::test]
    async fn test_get_tree_size_parse_error() {
        let app = Router::new().route(
            "/ct/v1/get-sth",
            get(|| async move { (StatusCode::OK, "not-json").into_response() }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = CtClient::new();
        let base = format!("http://{}", addr);
        let err = client.get_tree_size(&base).await.unwrap_err();
        assert!(format!("{err}").contains("Failed to parse STH response"));

        handle.abort();
    }
}
