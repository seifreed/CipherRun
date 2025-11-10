// HSTS Preload List Checker - Verify if domain is in browser preload lists

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    include_subdomains: bool,
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
    last_request: Arc<Mutex<Option<Instant>>>,
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
            last_request: Arc::new(Mutex::new(None)),
            cache_duration: Duration::from_secs(3600), // 1 hour cache
            rate_limit_duration: Duration::from_secs(1), // 1 second between requests
        }
    }

    /// Check if domain is in HSTS preload lists
    pub async fn check_preload_status(&self, domain: &str) -> Result<PreloadStatus, String> {
        // Normalize domain (remove www. prefix, lowercase)
        let normalized = Self::normalize_domain(domain);

        // Check cache first
        if let Some(cached) = self.get_from_cache(&normalized) {
            return Ok(cached);
        }

        // Apply rate limiting
        self.wait_for_rate_limit().await;

        // Try API query
        match self.query_api(&normalized).await {
            Ok(status) => {
                self.cache_status(&normalized, status.clone());
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
        let url = format!("https://hstspreload.org/api/v2/status?domain={}", domain);

        // Create HTTP client with timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
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

        // Parse JSON response
        let api_response: ApiResponse = response
            .json()
            .await
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
            // Firefox maintains separate list but largely mirrors Chromium
            in_firefox: is_preloaded,
            // Safari uses own list but also largely mirrors Chromium
            in_safari: is_preloaded,
            chromium_status: Some(chromium_status),
            source: PreloadSource::Api,
        }
    }

    /// Normalize domain for consistent cache keys
    fn normalize_domain(domain: &str) -> String {
        let mut normalized = domain.to_lowercase();

        // Remove www. prefix
        if normalized.starts_with("www.") {
            normalized = normalized[4..].to_string();
        }

        // Remove port if present
        if let Some(idx) = normalized.find(':') {
            normalized = normalized[..idx].to_string();
        }

        // Remove trailing dot
        if normalized.ends_with('.') {
            normalized.pop();
        }

        normalized
    }

    /// Get status from cache if available and not expired
    fn get_from_cache(&self, domain: &str) -> Option<PreloadStatus> {
        let cache = self.cache.lock().ok()?;

        if let Some(entry) = cache.get(domain)
            && entry.timestamp.elapsed() < self.cache_duration {
                let mut status = entry.status.clone();
                status.source = PreloadSource::Cache;
                return Some(status);
            }

        None
    }

    /// Cache preload status
    fn cache_status(&self, domain: &str, status: PreloadStatus) {
        if let Ok(mut cache) = self.cache.lock() {
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
        }
    }

    /// Wait for rate limit before making request
    async fn wait_for_rate_limit(&self) {
        if let Ok(mut last_request) = self.last_request.lock() {
            if let Some(last) = *last_request {
                let elapsed = last.elapsed();
                if elapsed < self.rate_limit_duration {
                    let wait_time = self.rate_limit_duration - elapsed;
                    tokio::time::sleep(wait_time).await;
                }
            }
            *last_request = Some(Instant::now());
        }
    }

    /// Clear the cache (useful for testing or forced refresh)
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        if let Ok(cache) = self.cache.lock() {
            let now = Instant::now();
            let valid_entries = cache
                .values()
                .filter(|entry| now.duration_since(entry.timestamp) < self.cache_duration)
                .count();
            (cache.len(), valid_entries)
        } else {
            (0, 0)
        }
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

        checker.cache_status("example.com", status);

        let cached = checker.get_from_cache("example.com");
        assert!(cached.is_some());

        let cached_status = cached.unwrap();
        assert_eq!(cached_status.source, PreloadSource::Cache);
        assert!(cached_status.in_chrome);
    }

    #[tokio::test]
    async fn test_api_conversion() {
        let api_response = ApiResponse {
            status: "preloaded".to_string(),
            include_subdomains: true,
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

        checker.cache_status("example1.com", status.clone());
        checker.cache_status("example2.com", status);

        let (total, valid) = checker.cache_stats();
        assert_eq!(total, 2);
        assert_eq!(valid, 2);
    }
}
