// Certificate Inventory - Domain management

use crate::Result;
use crate::certificates::parser::CertificateInfo;
use crate::utils::network::{canonical_target, split_target_host_port};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

pub use crate::monitor::types::AlertThresholds;

/// Maximum file size for domains file (10 MB)
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of domains in inventory
const MAX_DOMAINS: usize = 100_000;

pub(crate) fn canonical_inventory_key(hostname: &str, port: u16) -> String {
    let hostname = hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname);
    let normalized_hostname = hostname
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| hostname.to_ascii_lowercase());

    canonical_target(&normalized_hostname, port)
}

/// Monitored domain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredDomain {
    pub hostname: String,
    pub port: u16,
    pub enabled: bool,
    pub interval_seconds: u64,
    pub alert_thresholds: AlertThresholds,
    pub last_scan: Option<DateTime<Utc>>,
    pub last_certificate: Option<CertificateInfo>,
}

impl MonitoredDomain {
    /// Create a new monitored domain with default settings
    pub fn new(hostname: String, port: u16) -> Self {
        Self {
            hostname,
            port,
            enabled: true,
            interval_seconds: 3600, // Default 1 hour
            alert_thresholds: AlertThresholds::default(),
            last_scan: None,
            last_certificate: None,
        }
    }

    /// Create with custom interval
    pub fn with_interval(mut self, interval_seconds: u64) -> Self {
        self.interval_seconds = interval_seconds;
        self
    }

    /// Set alert thresholds
    pub fn with_thresholds(mut self, thresholds: AlertThresholds) -> Self {
        self.alert_thresholds = thresholds;
        self
    }

    /// Disable this domain
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Update last scan information
    pub fn update_scan(&mut self, certificate: Option<CertificateInfo>) {
        self.last_scan = Some(Utc::now());
        self.last_certificate = certificate;
    }

    /// Get domain identifier
    pub fn identifier(&self) -> String {
        canonical_inventory_key(&self.hostname, self.port)
    }
}

/// Certificate inventory - manages monitored domains
pub struct CertificateInventory {
    domains: HashMap<String, MonitoredDomain>,
}

impl CertificateInventory {
    /// Create new empty inventory
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    /// Add a domain to the inventory
    pub fn add_domain(&mut self, domain: MonitoredDomain) -> Result<()> {
        let key = domain.identifier();
        self.domains.insert(key, domain);
        Ok(())
    }

    /// Normalize a hostname into a consistent `host:port` key.
    /// If no port is specified, defaults to 443.
    fn normalize_key(hostname: &str) -> String {
        match split_target_host_port(hostname) {
            Ok((hostname, port)) => canonical_inventory_key(&hostname, port.unwrap_or(443)),
            Err(_) => hostname.to_ascii_lowercase(),
        }
    }

    /// Remove a domain from the inventory
    pub fn remove_domain(&mut self, hostname: &str) -> Result<()> {
        let key = Self::normalize_key(hostname);
        // Try exact key first, then fall back to raw hostname in case it was
        // stored without a port suffix
        if self.domains.remove(&key).is_none() && key != hostname {
            self.domains.remove(hostname);
        }
        Ok(())
    }

    /// Get a domain by hostname
    pub fn get_domain(&self, hostname: &str) -> Option<&MonitoredDomain> {
        let key = Self::normalize_key(hostname);
        self.domains.get(&key).or_else(|| {
            if key != hostname {
                self.domains.get(hostname)
            } else {
                None
            }
        })
    }

    /// Get a mutable reference to a domain
    pub fn get_domain_mut(&mut self, hostname: &str) -> Option<&mut MonitoredDomain> {
        let key = Self::normalize_key(hostname);
        if self.domains.contains_key(&key) {
            return self.domains.get_mut(&key);
        }
        if key != hostname {
            return self.domains.get_mut(hostname);
        }
        None
    }

    /// Get all enabled domains
    pub fn enabled_domains(&self) -> Vec<&MonitoredDomain> {
        self.domains.values().filter(|d| d.enabled).collect()
    }

    /// Get all domains
    pub fn all_domains(&self) -> Vec<&MonitoredDomain> {
        self.domains.values().collect()
    }

    /// Load domains from a file
    ///
    /// File format:
    /// ```text
    /// # Comments start with #
    /// example.com
    /// example.com:443 30m
    /// internal.corp.com:8443 5m
    /// badssl.com 1h
    /// ```
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_ref = path.as_ref();

        // Check file size before loading to prevent memory exhaustion
        let metadata = fs::metadata(path_ref)
            .map_err(|e| anyhow::anyhow!("Failed to read file metadata {:?}: {}", path_ref, e))?;

        if metadata.len() > MAX_FILE_SIZE {
            return Err(anyhow::anyhow!(
                "Domains file too large: {} bytes (max {} bytes)",
                metadata.len(),
                MAX_FILE_SIZE
            )
            .into());
        }

        let file = fs::File::open(path_ref)
            .map_err(|e| anyhow::anyhow!("Failed to open domains file {:?}: {}", path_ref, e))?;

        let reader = BufReader::new(file);
        let mut domain_count = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check domain count limit
            domain_count += 1;
            if domain_count > MAX_DOMAINS {
                tracing::warn!(
                    "Domains file contains more than {} entries, only the first {} will be loaded",
                    MAX_DOMAINS,
                    MAX_DOMAINS
                );
                break;
            }

            // Parse line: hostname[:port] [interval]
            // IPv6 with port must be bracketed, e.g. [2001:db8::1]:443
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let host_port = parts[0];
            let (hostname, port) = split_target_host_port(host_port)?;
            let port = port.unwrap_or(443);

            // Parse interval if provided
            let interval_seconds = if parts.len() > 1 {
                parse_interval(parts[1])?
            } else {
                3600 // Default 1 hour
            };

            let domain = MonitoredDomain::new(hostname, port).with_interval(interval_seconds);

            self.add_domain(domain)?;
        }

        Ok(())
    }

    /// Save domains to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.domains)
            .map_err(|e| anyhow::anyhow!("Failed to serialize inventory: {}", e))?;

        fs::write(path.as_ref(), json).map_err(|e| {
            anyhow::anyhow!("Failed to write inventory file {:?}: {}", path.as_ref(), e)
        })?;

        Ok(())
    }

    /// Load domains from JSON file
    pub fn load_from_json<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_ref = path.as_ref();

        // Check file size before loading to prevent memory exhaustion
        let metadata = fs::metadata(path_ref)
            .map_err(|e| anyhow::anyhow!("Failed to read file metadata {:?}: {}", path_ref, e))?;

        if metadata.len() > MAX_FILE_SIZE {
            return Err(anyhow::anyhow!(
                "Inventory JSON file too large: {} bytes (max {} bytes)",
                metadata.len(),
                MAX_FILE_SIZE
            )
            .into());
        }

        let contents = fs::read_to_string(path_ref)
            .map_err(|e| anyhow::anyhow!("Failed to read inventory file {:?}: {}", path_ref, e))?;

        let domains: HashMap<String, MonitoredDomain> = serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse inventory JSON: {}", e))?;

        if domains.len() > MAX_DOMAINS {
            return Err(anyhow::anyhow!(
                "Inventory JSON contains {} domains (max {})",
                domains.len(),
                MAX_DOMAINS
            )
            .into());
        }

        let mut normalized_domains = HashMap::with_capacity(domains.len());
        for domain in domains.into_values() {
            normalized_domains.insert(domain.identifier(), domain);
        }

        self.domains = normalized_domains;
        Ok(())
    }

    /// Get count of domains
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Check if inventory is empty
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Clear all domains
    pub fn clear(&mut self) {
        self.domains.clear();
    }
}

impl Default for CertificateInventory {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse interval string to seconds
///
/// Supported formats:
/// - "30s" - 30 seconds
/// - "5m" - 5 minutes
/// - "1h" - 1 hour
/// - "2d" - 2 days
/// - "3600" - 3600 seconds (plain number)
fn parse_interval(interval_str: &str) -> Result<u64> {
    if let Ok(seconds) = interval_str.parse::<u64>() {
        return Ok(seconds);
    }

    let interval_str = interval_str.to_lowercase();
    let len = interval_str.len();

    if len < 2 {
        return Err(anyhow::anyhow!("Invalid interval format: {}", interval_str).into());
    }

    let unit = &interval_str[len - 1..];
    let value = interval_str[..len - 1]
        .parse::<u64>()
        .map_err(|e| anyhow::anyhow!("Invalid interval value: {}", e))?;

    let seconds = match unit {
        "s" => Ok(value),
        "m" => value
            .checked_mul(60)
            .ok_or_else(|| anyhow::anyhow!("Interval overflow: value too large")),
        "h" => value
            .checked_mul(3600)
            .ok_or_else(|| anyhow::anyhow!("Interval overflow: value too large")),
        "d" => value
            .checked_mul(86400)
            .ok_or_else(|| anyhow::anyhow!("Interval overflow: value too large")),
        _ => {
            return Err(
                anyhow::anyhow!("Invalid interval unit: {} (use s, m, h, or d)", unit).into(),
            );
        }
    }?;

    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_monitored_domain_new() {
        let domain = MonitoredDomain::new("example.com".to_string(), 443);
        assert_eq!(domain.hostname, "example.com");
        assert_eq!(domain.port, 443);
        assert!(domain.enabled);
        assert_eq!(domain.interval_seconds, 3600);
    }

    #[test]
    fn test_monitored_domain_identifier() {
        let domain = MonitoredDomain::new("example.com".to_string(), 8443);
        assert_eq!(domain.identifier(), "example.com:8443");
    }

    #[test]
    fn test_monitored_domain_identifier_ipv6_is_bracketed() {
        let domain = MonitoredDomain::new("::1".to_string(), 443);
        assert_eq!(domain.identifier(), "[::1]:443");
    }

    #[test]
    fn test_monitored_domain_update_scan() {
        let mut domain = MonitoredDomain::new("example.com".to_string(), 443);
        assert!(domain.last_scan.is_none());
        domain.update_scan(None);
        assert!(domain.last_scan.is_some());
        assert!(domain.last_certificate.is_none());
    }

    #[test]
    fn test_inventory_add_remove() {
        let mut inventory = CertificateInventory::new();
        let domain = MonitoredDomain::new("example.com".to_string(), 443);

        inventory
            .add_domain(domain)
            .expect("test assertion should succeed");
        assert_eq!(inventory.len(), 1);

        inventory
            .remove_domain("example.com")
            .expect("test assertion should succeed");
        assert_eq!(inventory.len(), 0);
    }

    #[test]
    fn test_inventory_get_domain() {
        let mut inventory = CertificateInventory::new();
        let domain = MonitoredDomain::new("example.com".to_string(), 443);
        inventory
            .add_domain(domain)
            .expect("test assertion should succeed");

        let retrieved = inventory.get_domain("example.com");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hostname, "example.com");
    }

    #[test]
    fn test_inventory_domain_lookup_and_remove_are_case_insensitive() {
        let mut inventory = CertificateInventory::new();
        inventory
            .add_domain(MonitoredDomain::new("Example.COM".to_string(), 443))
            .expect("test assertion should succeed");

        assert!(inventory.get_domain("example.com").is_some());
        assert!(inventory.get_domain("EXAMPLE.COM:443").is_some());

        inventory
            .remove_domain("example.com")
            .expect("test assertion should succeed");
        assert_eq!(inventory.len(), 0);
    }

    #[test]
    fn test_inventory_get_domain_ipv6() {
        let mut inventory = CertificateInventory::new();
        inventory
            .add_domain(MonitoredDomain::new("::1".to_string(), 443))
            .expect("test assertion should succeed");

        let retrieved = inventory.get_domain("::1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hostname, "::1");

        inventory
            .remove_domain("::1")
            .expect("test assertion should succeed");
        assert_eq!(inventory.len(), 0);
    }

    #[test]
    fn test_inventory_get_domain_mut_updates() {
        let mut inventory = CertificateInventory::new();
        inventory
            .add_domain(MonitoredDomain::new("example.com".to_string(), 443))
            .expect("test assertion should succeed");

        if let Some(domain) = inventory.get_domain_mut("example.com") {
            domain.interval_seconds = 120;
        }

        let updated = inventory
            .get_domain("example.com")
            .expect("test assertion should succeed");
        assert_eq!(updated.interval_seconds, 120);
    }

    #[test]
    fn test_inventory_get_domain_mut_updates_ipv6_identifier() {
        let mut inventory = CertificateInventory::new();
        let domain = MonitoredDomain::new("::1".to_string(), 443);
        let identifier = domain.identifier();
        assert_eq!(identifier, "[::1]:443");

        inventory
            .add_domain(domain)
            .expect("test assertion should succeed");

        if let Some(domain) = inventory.get_domain_mut(&identifier) {
            domain.interval_seconds = 120;
        } else {
            panic!("expected IPv6 domain to be retrievable by identifier");
        }

        let updated = inventory
            .get_domain(&identifier)
            .expect("test assertion should succeed");
        assert_eq!(updated.interval_seconds, 120);
    }

    #[test]
    fn test_inventory_enabled_domains() {
        let mut inventory = CertificateInventory::new();

        let domain1 = MonitoredDomain::new("example.com".to_string(), 443);
        let domain2 = MonitoredDomain::new("disabled.com".to_string(), 443).disable();

        inventory
            .add_domain(domain1)
            .expect("test assertion should succeed");
        inventory
            .add_domain(domain2)
            .expect("test assertion should succeed");

        let enabled = inventory.enabled_domains();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].hostname, "example.com");
    }

    #[test]
    fn test_parse_interval() {
        assert_eq!(parse_interval("30s").unwrap(), 30);
        assert_eq!(parse_interval("5m").unwrap(), 300);
        assert_eq!(parse_interval("1h").unwrap(), 3600);
        assert_eq!(parse_interval("2d").unwrap(), 172800);
        assert_eq!(parse_interval("3600").unwrap(), 3600);
    }

    #[test]
    fn test_parse_interval_invalid() {
        assert!(parse_interval("30x").is_err());
        assert!(parse_interval("abc").is_err());
        assert!(parse_interval("").is_err());
    }

    #[test]
    fn test_load_from_file() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(
            temp_file,
            "# Test domains file\nexample.com\ntest.com:8443 30m\ninternal.local 1h"
        )?;

        let mut inventory = CertificateInventory::new();
        inventory.load_from_file(temp_file.path())?;

        assert_eq!(inventory.len(), 3);
        assert!(inventory.get_domain("example.com").is_some());
        assert!(inventory.get_domain("test.com:8443").is_some());

        let test_domain = inventory
            .get_domain("test.com:8443")
            .expect("test assertion should succeed");
        assert_eq!(test_domain.interval_seconds, 1800); // 30 minutes

        Ok(())
    }

    #[test]
    fn test_load_from_file_with_bracketed_ipv6() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "[::1]:443 30m")?;

        let mut inventory = CertificateInventory::new();
        inventory.load_from_file(temp_file.path())?;

        assert_eq!(inventory.len(), 1);
        assert!(inventory.get_domain("::1").is_some());
        assert!(inventory.get_domain("[::1]:443").is_some());
        Ok(())
    }

    #[test]
    fn test_load_from_file_invalid_port() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "example.com:notaport")?;

        let mut inventory = CertificateInventory::new();
        let result = inventory.load_from_file(temp_file.path());

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_load_from_file_invalid_target_format() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "example.com:443:extra")?;

        let mut inventory = CertificateInventory::new();
        let result = inventory.load_from_file(temp_file.path());

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_save_and_load_json() -> Result<()> {
        let temp_file = NamedTempFile::new()?;

        let mut inventory = CertificateInventory::new();
        inventory.add_domain(MonitoredDomain::new("example.com".to_string(), 443))?;
        inventory.add_domain(MonitoredDomain::new("test.com".to_string(), 8443))?;

        inventory.save_to_file(temp_file.path())?;

        let mut loaded_inventory = CertificateInventory::new();
        loaded_inventory.load_from_json(temp_file.path())?;

        assert_eq!(loaded_inventory.len(), 2);
        assert!(loaded_inventory.get_domain("example.com").is_some());
        assert!(loaded_inventory.get_domain("test.com:8443").is_some());

        Ok(())
    }
}
