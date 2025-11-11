// CT Log Sources Management
//
// Handles fetching and managing CT log sources from Google's CT log list

use super::Result;
use crate::error::TlsError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Google CT log list URL (v3 format)
const CT_LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

/// CT Log Source metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// Unique identifier for the log
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Log operator (e.g., "Google", "Cloudflare")
    pub operator: String,
    /// Base URL for the log API
    pub url: String,
    /// Public key (base64 encoded)
    pub key: Option<String>,
    /// Maximum merge delay in seconds
    pub mmd: Option<u64>,
    /// Current tree size (updated during streaming)
    pub tree_size: u64,
    /// Whether the log is currently usable
    pub usable: bool,
    /// Last error encountered (if any)
    pub last_error: Option<String>,
    /// Number of consecutive failures
    pub failure_count: u32,
}

impl LogSource {
    /// Check if this log source is healthy and should be used
    pub fn is_healthy(&self) -> bool {
        self.usable && self.failure_count < 3
    }

    /// Mark source as failed
    pub fn mark_failed(&mut self, error: String) {
        self.failure_count += 1;
        self.last_error = Some(error);
        if self.failure_count >= 3 {
            self.usable = false;
        }
    }

    /// Mark source as successful
    pub fn mark_success(&mut self) {
        self.failure_count = 0;
        self.last_error = None;
        self.usable = true;
    }
}

/// CT Log Source Manager
pub struct SourceManager {
    sources: HashMap<String, LogSource>,
    client: reqwest::Client,
}

impl SourceManager {
    /// Create a new SourceManager
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            sources: HashMap::new(),
            client,
        }
    }

    /// Fetch CT log sources from Google's log list
    pub async fn fetch_sources(&mut self) -> Result<()> {
        info!("Fetching CT log sources from {}", CT_LOG_LIST_URL);

        let response = self
            .client
            .get(CT_LOG_LIST_URL)
            .send()
            .await
            .map_err(|e| TlsError::Other(format!("Failed to fetch CT log list: {}", e)))?;

        if !response.status().is_success() {
            return Err(TlsError::HttpError {
                status: response.status().as_u16(),
                details: format!(
                    "CT log list request failed with status: {}",
                    response.status()
                ),
            });
        }

        let log_list: GoogleCtLogList =
            response.json().await.map_err(|e| TlsError::ParseError {
                message: format!("Failed to parse CT log list: {}", e),
            })?;

        debug!(
            "Fetched {} operators from CT log list",
            log_list.operators.len()
        );

        // Parse operators to get log sources
        for operator in &log_list.operators {
            for log in &operator.logs {
                // Only use usable logs
                if let Some(state) = &log.state
                    && state.usable.is_some()
                {
                    let log_id = log.log_id.clone();
                    let source = LogSource {
                        id: log_id.clone(),
                        description: log
                            .description
                            .clone()
                            .unwrap_or_else(|| format!("{} CT Log", operator.name)),
                        operator: operator.name.clone(),
                        url: log.url.clone(),
                        key: log.key.clone(),
                        mmd: log.mmd,
                        tree_size: 0,
                        usable: true,
                        last_error: None,
                        failure_count: 0,
                    };

                    self.sources.insert(log_id, source);
                }
            }
        }

        info!("Loaded {} usable CT log sources", self.sources.len());
        Ok(())
    }

    /// Get all healthy sources
    pub fn get_healthy_sources(&self) -> Vec<&LogSource> {
        self.sources.values().filter(|s| s.is_healthy()).collect()
    }

    /// Get a specific source by ID
    pub fn get_source(&self, id: &str) -> Option<&LogSource> {
        self.sources.get(id)
    }

    /// Get a mutable reference to a source
    pub fn get_source_mut(&mut self, id: &str) -> Option<&mut LogSource> {
        self.sources.get_mut(id)
    }

    /// Update tree size for a source
    pub fn update_tree_size(&mut self, id: &str, tree_size: u64) {
        if let Some(source) = self.sources.get_mut(id) {
            source.tree_size = tree_size;
        }
    }

    /// Mark source as failed
    pub fn mark_source_failed(&mut self, id: &str, error: String) {
        if let Some(source) = self.sources.get_mut(id) {
            source.mark_failed(error);
            warn!(
                "Source {} marked as failed (failure count: {})",
                id, source.failure_count
            );
        }
    }

    /// Mark source as successful
    pub fn mark_source_success(&mut self, id: &str) {
        if let Some(source) = self.sources.get_mut(id) {
            source.mark_success();
        }
    }

    /// Get total number of sources
    pub fn total_sources(&self) -> usize {
        self.sources.len()
    }

    /// Get number of healthy sources
    pub fn healthy_sources_count(&self) -> usize {
        self.sources.values().filter(|s| s.is_healthy()).count()
    }
}

impl Default for SourceManager {
    fn default() -> Self {
        Self::new()
    }
}

// Google CT Log List JSON structures
#[derive(Debug, Deserialize)]
struct GoogleCtLogList {
    operators: Vec<Operator>,
}

#[derive(Debug, Deserialize)]
struct Operator {
    name: String,
    #[serde(default)]
    logs: Vec<Log>,
}

#[derive(Debug, Deserialize)]
struct Log {
    log_id: String,
    description: Option<String>,
    url: String,
    key: Option<String>,
    mmd: Option<u64>,
    state: Option<LogState>,
}

#[derive(Debug, Deserialize)]
struct LogState {
    usable: Option<UsableState>,
}

#[derive(Debug, Deserialize)]
struct UsableState {
    // Empty struct used as marker - presence indicates log is usable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_source_health() {
        let mut source = LogSource {
            id: "test".to_string(),
            description: "Test Log".to_string(),
            operator: "Test Operator".to_string(),
            url: "https://example.com".to_string(),
            key: None,
            mmd: None,
            tree_size: 0,
            usable: true,
            last_error: None,
            failure_count: 0,
        };

        assert!(source.is_healthy());

        source.mark_failed("Test error".to_string());
        assert!(source.is_healthy());
        assert_eq!(source.failure_count, 1);

        source.mark_failed("Test error 2".to_string());
        source.mark_failed("Test error 3".to_string());
        assert!(!source.is_healthy());
        assert!(!source.usable);

        source.mark_success();
        assert!(source.is_healthy());
        assert_eq!(source.failure_count, 0);
    }

    #[test]
    fn test_source_manager_creation() {
        let manager = SourceManager::new();
        assert_eq!(manager.total_sources(), 0);
        assert_eq!(manager.healthy_sources_count(), 0);
    }
}
