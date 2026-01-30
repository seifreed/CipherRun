// Copyright (c) Marc Rivero López
// Licensed under GPLv3
// https://www.gnu.org/licenses/gpl-3.0.html

// DNS Cache Module - Performance Optimization
//
// This module provides a thread-safe DNS cache to reduce redundant DNS queries
// during mass scanning operations. The cache uses RwLock for concurrent access
// and implements time-based expiration to ensure DNS records remain fresh.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// DNS cache entry with timestamp
#[derive(Clone, Debug)]
struct DnsCacheEntry {
    ip_addresses: Vec<IpAddr>,
    timestamp: Instant,
}

/// Thread-safe DNS cache
///
/// Provides O(1) lookup performance with automatic expiration.
/// Uses Arc<RwLock<>> for safe concurrent access across async tasks.
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    ttl: Duration,
}

impl DnsCache {
    /// Create a new DNS cache with specified TTL
    ///
    /// # Arguments
    /// * `ttl` - Time-to-live for cache entries (recommended: 5-15 minutes)
    ///
    /// # Performance Characteristics
    /// - Memory: O(n) where n is number of unique hostnames
    /// - Lookup: O(1) average case
    /// - Insert: O(1) average case
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Create a default DNS cache with 10-minute TTL
    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(600))
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

impl DnsCache {
    /// Lookup hostname in cache
    ///
    /// Returns cached IP addresses if entry exists and is not expired.
    /// Uses read lock for concurrent access without blocking writers.
    pub async fn get(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(hostname) {
            // Check if entry is expired
            if entry.timestamp.elapsed() < self.ttl {
                return Some(entry.ip_addresses.clone());
            }
        }

        None
    }

    /// Insert hostname and IP addresses into cache
    ///
    /// Overwrites existing entries. Uses write lock to ensure consistency.
    pub async fn insert(&self, hostname: String, ip_addresses: Vec<IpAddr>) {
        let mut cache = self.cache.write().await;

        cache.insert(
            hostname,
            DnsCacheEntry {
                ip_addresses,
                timestamp: Instant::now(),
            },
        );
    }

    /// Clear all expired entries from cache
    ///
    /// This method should be called periodically to prevent unbounded growth.
    /// Returns the number of entries removed.
    pub async fn cleanup_expired(&self) -> usize {
        let mut cache = self.cache.write().await;
        let initial_size = cache.len();

        cache.retain(|_, entry| entry.timestamp.elapsed() < self.ttl);

        initial_size - cache.len()
    }

    /// Clear all entries from cache
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get current cache size
    pub async fn size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let total = cache.len();
        let expired = cache
            .values()
            .filter(|entry| entry.timestamp.elapsed() >= self.ttl)
            .count();

        CacheStats {
            total_entries: total,
            expired_entries: expired,
            active_entries: total - expired,
        }
    }
}

/// DNS cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub active_entries: usize,
}

/// Global DNS cache instance
///
/// Lazy initialization for zero-cost startup.
/// Shared across all scanning operations for maximum efficiency.
use std::sync::OnceLock;

static DNS_CACHE: OnceLock<DnsCache> = OnceLock::new();

/// Get the global DNS cache instance
pub fn global_cache() -> &'static DnsCache {
    DNS_CACHE.get_or_init(DnsCache::default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let hostname = "example.com".to_string();
        let ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];

        cache.insert(hostname.clone(), ips.clone()).await;

        let cached = cache.get(&hostname).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), ips);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = DnsCache::new(Duration::from_millis(100));
        let hostname = "example.com".to_string();
        let ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];

        cache.insert(hostname.clone(), ips).await;

        // Should be cached immediately
        assert!(cache.get(&hostname).await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        assert!(cache.get(&hostname).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache = DnsCache::new(Duration::from_millis(100));

        // Insert multiple entries
        cache
            .insert(
                "example1.com".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            )
            .await;
        cache
            .insert(
                "example2.com".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
            )
            .await;

        assert_eq!(cache.size().await, 2);

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Cleanup expired entries
        let removed = cache.cleanup_expired().await;
        assert_eq!(removed, 2);
        assert_eq!(cache.size().await, 0);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = DnsCache::new(Duration::from_secs(60));

        cache
            .insert(
                "example.com".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            )
            .await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.active_entries, 1);
        assert_eq!(stats.expired_entries, 0);
    }

    #[tokio::test]
    async fn test_ipv6_support() {
        let cache = DnsCache::default();
        let hostname = "ipv6.example.com".to_string();
        let ips = vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))];

        cache.insert(hostname.clone(), ips.clone()).await;

        let cached = cache.get(&hostname).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), ips);
    }
}
