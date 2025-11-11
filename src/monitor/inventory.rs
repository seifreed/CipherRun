// Certificate Inventory - Domain management

use crate::Result;
use crate::certificates::parser::CertificateInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub use crate::monitor::types::AlertThresholds;

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
        format!("{}:{}", self.hostname, self.port)
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

    /// Remove a domain from the inventory
    pub fn remove_domain(&mut self, hostname: &str) -> Result<()> {
        // Try with default port 443 if no port specified
        let key = if hostname.contains(':') {
            hostname.to_string()
        } else {
            format!("{}:443", hostname)
        };

        self.domains.remove(&key);
        Ok(())
    }

    /// Get a domain by hostname
    pub fn get_domain(&self, hostname: &str) -> Option<&MonitoredDomain> {
        // Try with default port 443 if no port specified
        let key = if hostname.contains(':') {
            hostname.to_string()
        } else {
            format!("{}:443", hostname)
        };

        self.domains.get(&key)
    }

    /// Get a mutable reference to a domain
    pub fn get_domain_mut(&mut self, hostname: &str) -> Option<&mut MonitoredDomain> {
        let key = if hostname.contains(':') {
            hostname.to_string()
        } else {
            format!("{}:443", hostname)
        };

        self.domains.get_mut(&key)
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
        let file = fs::File::open(path.as_ref()).map_err(|e| {
            anyhow::anyhow!("Failed to open domains file {:?}: {}", path.as_ref(), e)
        })?;

        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: hostname[:port] [interval]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let host_port = parts[0];
            let (hostname, port) = if host_port.contains(':') {
                let hp: Vec<&str> = host_port.split(':').collect();
                if hp.len() != 2 {
                    tracing::warn!("Invalid host:port format: {}", host_port);
                    continue;
                }
                let port = hp[1]
                    .parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("Invalid port number in {}: {}", host_port, e))?;
                (hp[0].to_string(), port)
            } else {
                (host_port.to_string(), 443)
            };

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
        let contents = fs::read_to_string(path.as_ref()).map_err(|e| {
            anyhow::anyhow!("Failed to read inventory file {:?}: {}", path.as_ref(), e)
        })?;

        let domains: HashMap<String, MonitoredDomain> = serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse inventory JSON: {}", e))?;

        self.domains = domains;
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
        "s" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86400,
        _ => {
            return Err(
                anyhow::anyhow!("Invalid interval unit: {} (use s, m, h, or d)", unit).into(),
            );
        }
    };

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
    fn test_inventory_add_remove() {
        let mut inventory = CertificateInventory::new();
        let domain = MonitoredDomain::new("example.com".to_string(), 443);

        inventory.add_domain(domain).unwrap();
        assert_eq!(inventory.len(), 1);

        inventory.remove_domain("example.com").unwrap();
        assert_eq!(inventory.len(), 0);
    }

    #[test]
    fn test_inventory_get_domain() {
        let mut inventory = CertificateInventory::new();
        let domain = MonitoredDomain::new("example.com".to_string(), 443);
        inventory.add_domain(domain).unwrap();

        let retrieved = inventory.get_domain("example.com");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hostname, "example.com");
    }

    #[test]
    fn test_inventory_enabled_domains() {
        let mut inventory = CertificateInventory::new();

        let domain1 = MonitoredDomain::new("example.com".to_string(), 443);
        let domain2 = MonitoredDomain::new("disabled.com".to_string(), 443).disable();

        inventory.add_domain(domain1).unwrap();
        inventory.add_domain(domain2).unwrap();

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

        let test_domain = inventory.get_domain("test.com:8443").unwrap();
        assert_eq!(test_domain.interval_seconds, 1800); // 30 minutes

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
