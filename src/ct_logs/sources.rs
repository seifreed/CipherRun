// CT Log Sources Management
//
// Handles fetching and managing CT log sources from Google's CT log list

use super::Result;
use crate::error::TlsError;
use crate::security::input_validation::{looks_like_dotted_ip_literal, looks_like_obfuscated_ip};
use crate::security::is_private_ip;
use crate::security::url::raw_url_host;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use tokio::net::lookup_host;
use tracing::{info, warn};

/// Google CT log list URL (v3 format)
pub(super) const CT_LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

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
        self.failure_count = self.failure_count.saturating_add(1);
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
            .unwrap_or_else(|_| {
                warn!(
                    event_name = "ct_log.sources.client.degraded_fallback",
                    error_type = "client_builder",
                    "HTTP client setup failed; using default client"
                );
                reqwest::Client::new()
            });

        Self {
            sources: HashMap::new(),
            client,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_sources(sources: impl IntoIterator<Item = LogSource>) -> Self {
        let mut manager = Self::new();
        manager.sources = sources
            .into_iter()
            .map(|source| (source.id.clone(), source))
            .collect();
        manager
    }

    /// Fetch CT log sources from Google's log list
    pub async fn fetch_sources(&mut self) -> Result<()> {
        self.fetch_sources_from(CT_LOG_LIST_URL, |url| async move {
            ct_log_url_resolves_publicly(&url).await
        })
        .await
    }

    pub(super) async fn fetch_sources_from<F, Fut>(
        &mut self,
        source_list_url: &str,
        resolve: F,
    ) -> Result<()>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = Result<bool>>,
    {
        let started = std::time::Instant::now();

        let response = self
            .client
            .get(source_list_url)
            .send()
            .await
            .map_err(|error| {
                warn!(
                    event_name = "ct_log.sources.fetch.failed",
                    error_type = "transport",
                    duration_ms = started.elapsed().as_millis() as u64,
                    "CT log source list request failed"
                );
                TlsError::Other(format!("Failed to fetch CT log list: {}", error))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            warn!(
                event_name = "ct_log.sources.fetch.failed",
                error_type = "http_status",
                http_status = status.as_u16(),
                duration_ms = started.elapsed().as_millis() as u64,
                "CT log source list request failed"
            );
            return Err(TlsError::HttpError {
                status: status.as_u16(),
                details: format!("CT log list request failed with status: {}", status),
            });
        }

        const MAX_CT_LOG_LIST_BYTES: u64 = 16 * 1024 * 1024;
        let body = crate::utils::http::read_response_body_capped(
            response,
            MAX_CT_LOG_LIST_BYTES,
            "CT log list",
        )
        .await
        .inspect_err(|_| {
            warn!(
                event_name = "ct_log.sources.fetch.failed",
                error_type = "response_body",
                duration_ms = started.elapsed().as_millis() as u64,
                "CT log source list response could not be read"
            );
        })?;
        let log_list: GoogleCtLogList = serde_json::from_slice(&body).map_err(|error| {
            warn!(
                event_name = "ct_log.sources.fetch.failed",
                error_type = "invalid_json",
                duration_ms = started.elapsed().as_millis() as u64,
                "CT log source list response was invalid"
            );
            TlsError::ParseError {
                message: format!("Failed to parse CT log list: {}", error),
            }
        })?;
        let operator_count = log_list.operators.len();

        // Parse operators to get log sources
        for operator in &log_list.operators {
            for log in &operator.logs {
                // Only use usable logs
                if let Some(state) = &log.state
                    && state.usable.is_some()
                {
                    if !is_valid_ct_log_url(&log.url) {
                        warn!(
                            event_name = "ct_log.skipped",
                            reason = "invalid_url",
                            "Skipping CT log source"
                        );
                        continue;
                    }
                    match resolve(log.url.clone()).await {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                event_name = "ct_log.skipped",
                                reason = "private_resolution",
                                "Skipping CT log source"
                            );
                            continue;
                        }
                        Err(_) => {
                            warn!(
                                event_name = "ct_log.skipped",
                                reason = "dns_resolution",
                                "Skipping CT log source"
                            );
                            continue;
                        }
                    }

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

        info!(
            event_name = "ct_log.sources.fetch.completed",
            outcome = "success",
            operator_count,
            source_count = self.sources.len(),
            duration_ms = started.elapsed().as_millis() as u64,
            "CT log sources loaded"
        );
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
                event_name = "ct_log.source.marked_failed",
                source_id = %id,
                failure_count = source.failure_count,
                usable = source.usable,
                "CT log source marked as failed"
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

fn is_valid_ct_log_url(url: &str) -> bool {
    if raw_url_host(url).is_some_and(|host| {
        looks_like_obfuscated_ip(host)
            || looks_like_dotted_ip_literal(host)
            || host.parse::<IpAddr>().is_ok()
    }) {
        return false;
    }

    url::Url::parse(url).is_ok_and(|url| {
        let host = url.host_str().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && !matches!(url.port(), Some(0))
            && host != "localhost"
        && !host.ends_with(".local")
        && !host.ends_with(".internal")
        && !matches!(url.host_str(), Some(host) if host.parse::<IpAddr>().is_ok_and(|ip| is_private_ip(&ip)))
        && !looks_like_obfuscated_ip(&host)
    })
}

pub(super) async fn ct_log_url_resolves_publicly(url: &str) -> Result<bool> {
    if let Some(host) = raw_url_host(url) {
        if looks_like_dotted_ip_literal(host) {
            return Err(TlsError::Other(
                "Invalid CT log host: dotted IP literal".to_string(),
            ));
        }
        if host.parse::<IpAddr>().is_ok() {
            return Err(TlsError::Other(
                "Invalid CT log host: IP literal".to_string(),
            ));
        }
        let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
        if normalized_host == "localhost"
            || normalized_host.ends_with(".local")
            || normalized_host.ends_with(".internal")
        {
            return Err(TlsError::Other(
                "Invalid CT log host: private/local host".to_string(),
            ));
        }
    }
    let parsed = url::Url::parse(url).map_err(|error| TlsError::Other(format!("{error}")))?;
    let raw_host = parsed
        .host_str()
        .ok_or_else(|| TlsError::Other("CT log URL missing host".to_string()))?
        .to_string();
    let host = raw_host.trim_end_matches('.');
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<_> = lookup_host((host, port))
        .await
        .map_err(|error| TlsError::Other(format!("Failed to resolve CT log host {host}: {error}")))?
        .collect();
    Ok(resolved_addresses_are_public(&addrs))
}

fn resolved_addresses_are_public(addrs: &[std::net::SocketAddr]) -> bool {
    !addrs.is_empty() && addrs.iter().all(|addr| !is_private_ip(&addr.ip()))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_ct_log_response(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local HTTP fixture should bind");
        let address = listener
            .local_addr()
            .expect("local HTTP fixture should have an address");
        tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("HTTP client should connect to local fixture");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let reason = if status == 200 {
                "OK"
            } else {
                "Service Unavailable"
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("HTTP fixture response should be written");
        });
        format!("http://{address}/log-list.json")
    }

    async fn serve_oversized_ct_log_response() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local HTTP fixture should bind");
        let address = listener
            .local_addr()
            .expect("local HTTP fixture should have an address");
        tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("HTTP client should connect to local fixture");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("oversized HTTP fixture response should be written");
        });
        format!("http://{address}/log-list.json")
    }

    async fn serve_truncated_ct_log_response() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local HTTP fixture should bind");
        let address = listener
            .local_addr()
            .expect("local HTTP fixture should have an address");
        tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("HTTP client should connect to local fixture");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"operators\":[]}")
                .await
                .expect("truncated HTTP fixture response should be written");
        });
        format!("http://{address}/log-list.json")
    }

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
    fn test_log_source_failure_count_saturates() {
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
            failure_count: u32::MAX,
        };

        source.mark_failed("overflow".to_string());

        assert_eq!(source.failure_count, u32::MAX);
        assert!(!source.usable);
        assert_eq!(source.last_error.as_deref(), Some("overflow"));
    }

    #[test]
    fn test_source_manager_creation() {
        let manager = SourceManager::new();
        assert_eq!(manager.total_sources(), 0);
        assert_eq!(manager.healthy_sources_count(), 0);
    }

    #[tokio::test]
    async fn fetch_sources_parses_and_filters_entries_with_injected_resolution() {
        let body = r#"{
            "operators": [{
                "name": "Example operator",
                "logs": [
                    {
                        "log_id": "public",
                        "url": "https://ct.example.com",
                        "state": {"usable": {}}
                    },
                    {
                        "log_id": "private",
                        "url": "https://private.example.com",
                        "state": {"usable": {}}
                    },
                    {
                        "log_id": "dns-error",
                        "url": "https://unresolved.example.com",
                        "state": {"usable": {}}
                    },
                    {
                        "log_id": "invalid-url",
                        "url": "file:///tmp/log",
                        "state": {"usable": {}}
                    },
                    {
                        "log_id": "unusable",
                        "url": "https://ignored.example.com"
                    }
                ]
            }]
        }"#;
        let url = serve_ct_log_response(200, body).await;
        let mut manager = SourceManager::new();

        manager
            .fetch_sources_from(&url, |log_url| {
                std::future::ready(match log_url.as_str() {
                    "https://ct.example.com" => Ok(true),
                    "https://private.example.com" => Ok(false),
                    "https://unresolved.example.com" => {
                        Err(TlsError::Other("fixture DNS failure".to_string()))
                    }
                    _ => panic!("unexpected log URL passed to resolver: {log_url}"),
                })
            })
            .await
            .expect("a valid CT log list should be processed");

        assert_eq!(manager.total_sources(), 1);
        let source = manager
            .get_source("public")
            .expect("public usable source should be retained");
        assert_eq!(source.description, "Example operator CT Log");
        assert_eq!(source.operator, "Example operator");
        assert_eq!(source.url, "https://ct.example.com");
        assert_eq!(source.failure_count, 0);
        assert!(manager.get_source("private").is_none());
        assert!(manager.get_source("dns-error").is_none());
        assert!(manager.get_source("invalid-url").is_none());
        assert!(manager.get_source("unusable").is_none());
    }

    #[tokio::test]
    async fn fetch_sources_maps_http_status_and_invalid_json_errors() {
        let error_url = serve_ct_log_response(503, "temporarily unavailable").await;
        let mut manager = SourceManager::new();
        let status_error = manager
            .fetch_sources_from(&error_url, |_| std::future::ready(Ok(true)))
            .await
            .expect_err("non-success HTTP status should fail source loading");
        assert!(status_error.to_string().contains("503"));

        let invalid_json_url = serve_ct_log_response(200, "not-json").await;
        let json_error = manager
            .fetch_sources_from(&invalid_json_url, |_| std::future::ready(Ok(true)))
            .await
            .expect_err("malformed JSON should fail source loading");
        assert!(
            json_error
                .to_string()
                .contains("Failed to parse CT log list")
        );
    }

    #[tokio::test]
    async fn fetch_sources_rejects_oversized_bodies_and_transport_failures() {
        let oversized_url = serve_oversized_ct_log_response().await;
        let mut manager = SourceManager::new();
        let body_error = manager
            .fetch_sources_from(&oversized_url, |_| std::future::ready(Ok(true)))
            .await
            .expect_err("an oversized CT log-list body should be rejected");
        assert!(body_error.to_string().contains("response too large"));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("closed-port fixture should bind");
        let address = listener.local_addr().unwrap();
        drop(listener);
        let transport_error = manager
            .fetch_sources_from(&format!("http://{address}/log-list.json"), |_| {
                std::future::ready(Ok(true))
            })
            .await
            .expect_err("a refused CT log-list request should be an error");
        assert!(
            transport_error
                .to_string()
                .contains("Failed to fetch CT log list")
        );
    }

    #[tokio::test]
    async fn fetch_sources_reports_a_truncated_response_body() {
        let truncated_url = serve_truncated_ct_log_response().await;
        let mut manager = SourceManager::new();

        let error = manager
            .fetch_sources_from(&truncated_url, |_| std::future::ready(Ok(true)))
            .await
            .expect_err("a truncated CT log-list body should fail");

        assert!(error.to_string().contains("Failed to read CT log list"));
    }

    #[test]
    fn test_is_valid_ct_log_url_rejects_unsafe_urls() {
        assert!(is_valid_ct_log_url("https://ct.example.com"));
        assert!(is_valid_ct_log_url("http://ct.example.com"));
        assert!(!is_valid_ct_log_url("file:///tmp/log"));
        assert!(!is_valid_ct_log_url("https://user@example.com"));
        assert!(!is_valid_ct_log_url("https://example.com:0"));
        assert!(!is_valid_ct_log_url("https://"));
        assert!(!is_valid_ct_log_url("https://localhost"));
        assert!(!is_valid_ct_log_url("https://localhost."));
        assert!(!is_valid_ct_log_url("https://127.0.0.1"));
        assert!(!is_valid_ct_log_url("https://8.8.8.8"));
        assert!(!is_valid_ct_log_url("https://2130706433"));
        assert!(!is_valid_ct_log_url("https://127.1"));
        assert!(!is_valid_ct_log_url("https://0x7f000001"));
    }

    #[test]
    fn test_is_valid_ct_log_url_rejects_dotted_ip_literal() {
        assert!(!is_valid_ct_log_url("https://10.0.0.1./log"));
    }

    #[tokio::test]
    async fn test_ct_log_url_resolves_publicly_rejects_localhost() {
        assert!(
            ct_log_url_resolves_publicly("https://localhost")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_ct_log_url_resolves_publicly_rejects_private_hostnames() {
        assert!(
            ct_log_url_resolves_publicly("https://ct.internal/log")
                .await
                .is_err()
        );
        assert!(
            ct_log_url_resolves_publicly("https://10.0.0.1/log")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_ct_log_url_resolves_publicly_rejects_ip_literals() {
        assert!(
            ct_log_url_resolves_publicly("https://8.8.8.8/log")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_ct_log_url_resolves_publicly_rejects_dotted_ip_literal() {
        assert!(
            ct_log_url_resolves_publicly("https://10.0.0.1./log")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_ct_log_url_resolves_publicly_errors_on_unresolved_host() {
        assert!(
            ct_log_url_resolves_publicly("https://invalid.invalid")
                .await
                .is_err()
        );
    }

    #[test]
    fn resolved_addresses_must_be_nonempty_and_public() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        assert!(!resolved_addresses_are_public(&[]));
        assert!(resolved_addresses_are_public(&[SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        )]));
        assert!(!resolved_addresses_are_public(&[SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            443,
        )]));
        assert!(!resolved_addresses_are_public(&[SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            443,
        )]));
    }

    #[test]
    fn test_source_manager_updates_and_failures() {
        let mut manager = SourceManager::new();
        manager.sources.insert(
            "log1".to_string(),
            LogSource {
                id: "log1".to_string(),
                description: "Test Log".to_string(),
                operator: "Test Operator".to_string(),
                url: "https://example.com".to_string(),
                key: None,
                mmd: None,
                tree_size: 0,
                usable: true,
                last_error: None,
                failure_count: 0,
            },
        );

        manager.update_tree_size("log1", 42);
        assert_eq!(manager.get_source("log1").unwrap().tree_size, 42);
        manager.update_tree_size("missing", 99);
        assert_eq!(manager.get_source("log1").unwrap().tree_size, 42);

        manager.mark_source_failed("log1", "oops".to_string());
        let source = manager.get_source("log1").unwrap();
        assert_eq!(source.failure_count, 1);
        assert!(source.last_error.as_deref().unwrap_or("").contains("oops"));

        manager.mark_source_success("log1");
        manager.mark_source_failed("missing", "ignored".to_string());
        manager.mark_source_success("missing");
        let source = manager.get_source("log1").unwrap();
        assert_eq!(source.failure_count, 0);
        assert!(source.last_error.is_none());
        assert!(source.usable);
        assert_eq!(manager.healthy_sources_count(), 1);
        assert_eq!(manager.get_healthy_sources().len(), 1);
        assert!(manager.get_source("missing").is_none());
    }
}
