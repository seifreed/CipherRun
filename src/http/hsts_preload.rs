// HSTS Preload List Checker - Verify if domain is in browser preload lists

use crate::security::input_validation::{looks_like_dotted_ip_literal, looks_like_obfuscated_ip};
use crate::constants::HTTP_REQUEST_TIMEOUT;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as TokioMutex;

/// HSTS Preload status across browsers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreloadStatus {
    pub in_chrome: bool,
    pub in_firefox: bool,
    pub in_edge: bool,
    pub in_safari: bool,
    pub chromium_status: Option<String>, // "pending", "preloaded", "rejected", "unknown"
    pub source: PreloadSource,
}

/// Source of preload status information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreloadSource {
    /// Fetched from hstspreload.org API
    Api,
    /// Retrieved from cache
    Cache,
    /// Error occurred during check
    Error(String),
}

/// Response from hstspreload.org API
#[derive(Debug, Deserialize)]
struct ApiResponse {
    status: String,
    #[serde(default)]
    chrome: Option<ChromeStatus>,
}

#[derive(Debug, Deserialize)]
struct ChromeStatus {
    status: String,
}

/// Cache entry for preload status
#[derive(Clone)]
struct CacheEntry {
    status: PreloadStatus,
    timestamp: Instant,
}

/// HSTS Preload Checker with caching and rate limiting
pub struct HstsPreloadChecker {
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    last_request: Arc<TokioMutex<Option<Instant>>>,
    cache_duration: Duration,
    rate_limit_duration: Duration,
}

impl Default for HstsPreloadChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl HstsPreloadChecker {
    /// Create a new HSTS preload checker
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            last_request: Arc::new(TokioMutex::new(None)),
            cache_duration: crate::constants::HSTS_CACHE_DURATION,
            rate_limit_duration: crate::constants::HSTS_RATE_LIMIT_INTERVAL,
        }
    }

    /// Check if domain is in HSTS preload lists
    pub async fn check_preload_status(&self, domain: &str) -> Result<PreloadStatus, String> {
        if looks_like_obfuscated_ip(domain.trim()) {
            return Err("HSTS preload lookup does not accept obfuscated IP notation".to_string());
        }
        if looks_like_dotted_ip_literal(domain.trim()) {
            return Err("HSTS preload lookup does not accept dotted IP literals".to_string());
        }

        // Normalize domain (remove www. prefix, lowercase)
        let normalized = Self::normalize_domain(domain);

        // Check cache first
        if let Some(cached) = self.get_from_cache(&normalized)? {
            return Ok(cached);
        }

        // Apply rate limiting
        self.wait_for_rate_limit().await;

        // Try API query
        match self.query_api(&normalized).await {
            Ok(status) => {
                self.cache_status(&normalized, status.clone())?;
                Ok(status)
            }
            Err(api_error) => {
                // Fallback: create error status
                let status = PreloadStatus {
                    in_chrome: false,
                    in_firefox: false,
                    in_edge: false,
                    in_safari: false,
                    chromium_status: Some("unknown".to_string()),
                    source: PreloadSource::Error(api_error),
                };
                Ok(status)
            }
        }
    }

    /// Query hstspreload.org API
    async fn query_api(&self, domain: &str) -> Result<PreloadStatus, String> {
        let encoded_domain = urlencoding::encode(domain);
        let url = format!(
            "https://hstspreload.org/api/v2/status?domain={}",
            encoded_domain
        );

        // Create HTTP client with timeout
        let client = reqwest::Client::builder()
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        // Make request
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        // Check status code
        if !response.status().is_success() {
            return Err(format!("API returned status: {}", response.status()));
        }

        const MAX_HSTS_PRELOAD_BYTES: u64 = 1024 * 1024;
        let body = crate::utils::http::read_response_body_capped(
            response,
            MAX_HSTS_PRELOAD_BYTES,
            "HSTS preload response",
        )
        .await
        .map_err(|e| e.to_string())?;
        let api_response: ApiResponse = serde_json::from_slice(&body)
            .map_err(|e| format!("Failed to parse API response: {}", e))?;

        // Convert to PreloadStatus
        Ok(Self::convert_api_response(api_response))
    }

    /// Convert API response to PreloadStatus
    fn convert_api_response(api_response: ApiResponse) -> PreloadStatus {
        let chromium_status = api_response
            .chrome
            .as_ref()
            .map(|c| c.status.clone())
            .unwrap_or_else(|| api_response.status.clone());

        // Determine browser status
        let is_preloaded = chromium_status == "preloaded";

        PreloadStatus {
            // Chromium-based browsers (Chrome, Edge, Opera, Brave, etc.)
            in_chrome: is_preloaded,
            in_edge: is_preloaded, // Edge uses Chromium list
            // Firefox and Safari maintain separate lists; the hstspreload.org API
            // only provides Chromium status, so these are best-effort approximations.
            // In practice the lists overlap heavily but are not identical.
            in_firefox: is_preloaded,
            in_safari: is_preloaded,
            chromium_status: Some(chromium_status),
            source: PreloadSource::Api,
        }
    }

    /// Normalize domain for consistent cache keys
    fn normalize_domain(domain: &str) -> String {
        let domain = domain.trim();
        let mut normalized = if domain.contains("://")
            && let Ok(url) = url::Url::parse(domain)
            && matches!(url.scheme(), "http" | "https")
            && let Some(host) = url.host_str()
        {
            host.to_ascii_lowercase()
        } else {
            let mut normalized = domain.to_ascii_lowercase();
            if let Some(stripped) = normalized.strip_prefix("https://") {
                normalized = stripped.to_string();
            } else if let Some(stripped) = normalized.strip_prefix("http://") {
                normalized = stripped.to_string();
            }
            normalized
        };

        if let Some(stripped) = normalized.strip_prefix('[')
            && let Some(host) = stripped.strip_suffix(']')
        {
            normalized = host.to_string();
        }

        if let Some(idx) = normalized.find(['/', '?', '#']) {
            normalized.truncate(idx);
        }

        // Remove www. prefix (ensure we don't create empty string)
        if let Some(stripped) = normalized.strip_prefix("www.")
            && !stripped.is_empty()
        {
            normalized = stripped.to_string();
        }

        // Remove host:port suffix, but do not truncate raw IPv6 literals.
        if normalized.matches(':').count() == 1
            && let Some(idx) = normalized.find(':')
            && idx > 0
        {
            normalized = normalized.get(..idx).unwrap_or_default().to_string();
        }

        // Remove trailing dot
        if normalized.ends_with('.') && normalized.len() > 1 {
            normalized.pop();
        }

        normalized
    }

    /// Get status from cache if available and not expired
    fn get_from_cache(&self, domain: &str) -> Result<Option<PreloadStatus>, String> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| "HSTS preload cache lock poisoned".to_string())?;

        if let Some(entry) = cache.get(domain)
            && entry.timestamp.elapsed() < self.cache_duration
        {
            let mut status = entry.status.clone();
            status.source = PreloadSource::Cache;
            return Ok(Some(status));
        }

        Ok(None)
    }

    /// Cache preload status
    fn cache_status(&self, domain: &str, status: PreloadStatus) -> Result<(), String> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| "HSTS preload cache lock poisoned".to_string())?;
        cache.insert(
            domain.to_string(),
            CacheEntry {
                status,
                timestamp: Instant::now(),
            },
        );

        // Clean expired entries if cache is getting large
        if cache.len() > 1000 {
            let now = Instant::now();
            cache.retain(|_, entry| now.duration_since(entry.timestamp) < self.cache_duration);
        }
        Ok(())
    }

    /// Wait for rate limit before making request
    ///
    /// Holds a tokio::sync::Mutex across the sleep to properly serialize
    /// concurrent callers, preventing multiple requests from firing simultaneously.
    async fn wait_for_rate_limit(&self) {
        let mut last_request = self.last_request.lock().await;

        if let Some(last) = *last_request {
            let elapsed = last.elapsed();
            if elapsed < self.rate_limit_duration {
                tokio::time::sleep(self.rate_limit_duration - elapsed).await;
            }
        }

        *last_request = Some(Instant::now());
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> Result<(usize, usize), String> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| "HSTS preload cache lock poisoned".to_string())?;
        let now = Instant::now();
        let valid_entries = cache
            .values()
            .filter(|entry| now.duration_since(entry.timestamp) < self.cache_duration)
            .count();
        Ok((cache.len(), valid_entries))
    }
}

/// Top 100 preloaded domains (fallback list for offline mode)
/// This is a subset of the full list maintained by browsers
const KNOWN_PRELOADED_DOMAINS: &[&str] = &[
    "google.com",
    "google.co.uk",
    "gmail.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "mozilla.org",
    "wikipedia.org",
    "yahoo.com",
    "linkedin.com",
    "netflix.com",
    "instagram.com",
    "reddit.com",
    "stackoverflow.com",
    "dropbox.com",
    "paypal.com",
    "live.com",
    "office.com",
    "wordpress.com",
    "tumblr.com",
    "blogger.com",
    "medium.com",
    "slack.com",
    "zoom.us",
    "adobe.com",
    "bing.com",
    "twitch.tv",
    "vimeo.com",
    "snapchat.com",
    "whatsapp.com",
    "telegram.org",
    "discord.com",
    "spotify.com",
    "soundcloud.com",
    "vk.com",
    "baidu.com",
    "yandex.ru",
    "aliexpress.com",
    "ebay.com",
    "booking.com",
    "airbnb.com",
    "uber.com",
    "lyft.com",
    "salesforce.com",
    "oracle.com",
    "ibm.com",
    "intel.com",
    "nvidia.com",
    "amd.com",
    "dell.com",
    "hp.com",
    "cisco.com",
    "vmware.com",
    "redhat.com",
    "canonical.com",
    "docker.com",
    "kubernetes.io",
    "gitlab.com",
    "bitbucket.org",
    "aws.amazon.com",
    "azure.com",
    "cloud.google.com",
    "heroku.com",
    "digitalocean.com",
    "linode.com",
    "vultr.com",
    "namecheap.com",
    "godaddy.com",
    "hover.com",
    "fastmail.com",
    "protonmail.com",
    "tutanota.com",
    "mailchimp.com",
    "sendgrid.com",
    "stripe.com",
    "square.com",
    "venmo.com",
    "cashapp.com",
    "coinbase.com",
    "kraken.com",
    "binance.com",
    "bitfinex.com",
    "bitstamp.net",
    "gdax.com",
    "gemini.com",
    "atlassian.com",
    "jira.com",
    "confluence.com",
    "trello.com",
    "asana.com",
    "monday.com",
    "notion.so",
    "airtable.com",
    "figma.com",
    "canva.com",
];

/// Check if domain is in the static preloaded list
pub fn is_in_static_list(domain: &str) -> bool {
    let normalized = HstsPreloadChecker::normalize_domain(domain);
    KNOWN_PRELOADED_DOMAINS.contains(&normalized.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_normalization() {
        assert_eq!(
            HstsPreloadChecker::normalize_domain("WWW.EXAMPLE.COM"),
            "example.com"
        );
        assert_eq!(
            HstsPreloadChecker::normalize_domain("example.com:443"),
            "example.com"
        );
        assert_eq!(
            HstsPreloadChecker::normalize_domain("example.com."),
            "example.com"
        );
        assert_eq!(
            HstsPreloadChecker::normalize_domain("www.example.com:443"),
            "example.com"
        );
        assert_eq!(
            HstsPreloadChecker::normalize_domain("https://www.example.com:443/path?q=1"),
            "example.com"
        );
        assert_eq!(
            HstsPreloadChecker::normalize_domain("https://user:pass@www.example.com:443/path"),
            "example.com"
        );
        assert_eq!(
            HstsPreloadChecker::normalize_domain("https://[2001:db8::1]:443/path"),
            "2001:db8::1"
        );
    }

    #[tokio::test]
    async fn test_check_preload_status_rejects_obfuscated_ip_notation() {
        let checker = HstsPreloadChecker::new();
        let err = checker
            .check_preload_status("127.1")
            .await
            .expect_err("obfuscated IP should be rejected");

        assert!(err.contains("obfuscated IP notation"));
    }

    #[tokio::test]
    async fn test_check_preload_status_rejects_dotted_ip_literal() {
        let checker = HstsPreloadChecker::new();
        let err = checker
            .check_preload_status("127.0.0.1.")
            .await
            .expect_err("dotted IP should be rejected");

        assert!(err.contains("dotted IP literals"));
    }

    #[test]
    fn test_static_list() {
        assert!(is_in_static_list("google.com"));
        assert!(is_in_static_list("www.google.com"));
        assert!(is_in_static_list("GOOGLE.COM"));
        assert!(!is_in_static_list("example.com"));
    }

    #[tokio::test]
    async fn test_cache() {
        let checker = HstsPreloadChecker::new();

        let status = PreloadStatus {
            in_chrome: true,
            in_firefox: true,
            in_edge: true,
            in_safari: true,
            chromium_status: Some("preloaded".to_string()),
            source: PreloadSource::Api,
        };

        checker
            .cache_status("example.com", status)
            .expect("cache should update");

        let cached = checker
            .get_from_cache("example.com")
            .expect("cache should read");
        assert!(cached.is_some());

        let cached_status = cached.expect("test assertion should succeed");
        assert_eq!(cached_status.source, PreloadSource::Cache);
        assert!(cached_status.in_chrome);
    }

    #[tokio::test]
    async fn test_api_conversion() {
        let api_response = ApiResponse {
            status: "preloaded".to_string(),
            chrome: Some(ChromeStatus {
                status: "preloaded".to_string(),
            }),
        };

        let status = HstsPreloadChecker::convert_api_response(api_response);
        assert!(status.in_chrome);
        assert!(status.in_firefox);
        assert!(status.in_edge);
        assert!(status.in_safari);
        assert_eq!(status.chromium_status, Some("preloaded".to_string()));
    }

    #[test]
    fn test_cache_stats() {
        let checker = HstsPreloadChecker::new();

        let status = PreloadStatus {
            in_chrome: true,
            in_firefox: true,
            in_edge: true,
            in_safari: true,
            chromium_status: Some("preloaded".to_string()),
            source: PreloadSource::Api,
        };

        checker
            .cache_status("example1.com", status.clone())
            .expect("cache should update");
        checker
            .cache_status("example2.com", status)
            .expect("cache should update");

        let (total, valid) = checker.cache_stats().expect("cache stats should read");
        assert_eq!(total, 2);
        assert_eq!(valid, 2);
    }

    #[tokio::test]
    async fn test_poisoned_cache_lock_returns_error() {
        let checker = HstsPreloadChecker::new();
        let cache = checker.cache.clone();
        let _ = std::thread::spawn(move || {
            let _guard = cache.lock().expect("lock should acquire");
            panic!("poison cache lock");
        })
        .join();

        let err = checker
            .check_preload_status("example.com")
            .await
            .expect_err("poisoned cache lock should fail");
        assert!(err.contains("HSTS preload cache lock poisoned"));
    }

    #[test]
    fn test_poisoned_cache_stats_lock_returns_error() {
        let checker = HstsPreloadChecker::new();
        let cache = checker.cache.clone();
        let _ = std::thread::spawn(move || {
            let _guard = cache.lock().expect("lock should acquire");
            panic!("poison cache lock");
        })
        .join();

        let err = checker
            .cache_stats()
            .expect_err("poisoned cache stats lock should fail");
        assert!(err.contains("HSTS preload cache lock poisoned"));
    }
}
