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
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { client }
    }

    /// Get the current tree size (STH - Signed Tree Head)
    pub async fn get_tree_size(&self, log_url: &str) -> Result<u64> {
        let url = format!("{}/ct/v1/get-sth", log_url.trim_end_matches('/'));

        let response = self
            .retry_request(|| async { self.client.get(&url).send().await })
            .await?;

        let sth: SignedTreeHead = response.json().await.map_err(|e| {
            TlsError::ParseError { message: format!("Failed to parse STH response: {}", e) }
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
        let url = format!(
            "{}/ct/v1/get-entries?start={}&end={}",
            log_url.trim_end_matches('/'),
            start,
            end
        );

        debug!("Fetching entries from {} to {}", start, end);

        let response = self
            .retry_request(|| async { self.client.get(&url).send().await })
            .await?;

        let entries_response: EntriesResponse = response.json().await.map_err(|e| {
            TlsError::ParseError { message: format!("Failed to parse entries response: {}", e) }
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
                            details: format!("Request failed with status: {}", response.status())
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

    #[test]
    fn test_client_creation() {
        let client = CtClient::new();
        assert!(std::ptr::addr_of!(client.client) as usize != 0);
    }
}
