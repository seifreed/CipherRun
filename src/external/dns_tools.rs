// DNS tools integration - dig and host
// Extended DNS lookups for target discovery

use crate::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    A,
    AAAA,
    MX,
    CNAME,
    TXT,
    NS,
    SOA,
    PTR,
    SRV,
    CAA,
    TLSA,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::MX => "MX",
            RecordType::CNAME => "CNAME",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
            RecordType::PTR => "PTR",
            RecordType::SRV => "SRV",
            RecordType::CAA => "CAA",
            RecordType::TLSA => "TLSA",
        }
    }
}

/// DNS lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupResult {
    pub domain: String,
    pub record_type: String,
    pub records: Vec<String>,
    pub ttl: Option<u32>,
    pub raw_output: String,
}

/// dig wrapper
pub struct Dig {
    dig_path: String,
}

impl Default for Dig {
    fn default() -> Self {
        Self::new()
    }
}

impl Dig {
    pub fn new() -> Self {
        Self {
            dig_path: "dig".to_string(),
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { dig_path: path }
    }

    /// Check if dig is available
    pub fn is_available(&self) -> bool {
        Command::new(&self.dig_path)
            .arg("-v")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Lookup DNS record
    pub fn lookup(&self, domain: &str, record_type: RecordType) -> Result<DnsLookupResult> {
        let output = Command::new(&self.dig_path)
            .arg(domain)
            .arg(record_type.as_str())
            .arg("+short")
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let records: Vec<String> = stdout
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| line.trim().to_string())
                .collect();

            Ok(DnsLookupResult {
                domain: domain.to_string(),
                record_type: record_type.as_str().to_string(),
                records,
                ttl: None,
                raw_output: stdout,
            })
        } else {
            Err(anyhow::anyhow!(
                "dig lookup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// Lookup with detailed output
    pub fn lookup_detailed(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<DnsLookupResult> {
        let output = Command::new(&self.dig_path)
            .arg(domain)
            .arg(record_type.as_str())
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let (records, ttl) = parse_dig_output(&stdout, record_type);

            Ok(DnsLookupResult {
                domain: domain.to_string(),
                record_type: record_type.as_str().to_string(),
                records,
                ttl,
                raw_output: stdout,
            })
        } else {
            Err(anyhow::anyhow!(
                "dig detailed lookup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// Reverse DNS lookup
    pub fn reverse_lookup(&self, ip: &str) -> Result<Vec<String>> {
        let output = Command::new(&self.dig_path)
            .arg("-x")
            .arg(ip)
            .arg("+short")
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let records: Vec<String> = stdout
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| line.trim().to_string())
                .collect();

            Ok(records)
        } else {
            Err(anyhow::anyhow!(
                "dig reverse lookup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// Query specific nameserver
    pub fn query_nameserver(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: &str,
    ) -> Result<DnsLookupResult> {
        let output = Command::new(&self.dig_path)
            .arg(format!("@{}", nameserver))
            .arg(domain)
            .arg(record_type.as_str())
            .arg("+short")
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let records: Vec<String> = stdout
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| line.trim().to_string())
                .collect();

            Ok(DnsLookupResult {
                domain: domain.to_string(),
                record_type: record_type.as_str().to_string(),
                records,
                ttl: None,
                raw_output: stdout,
            })
        } else {
            Err(anyhow::anyhow!(
                "dig nameserver query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

/// host wrapper
pub struct Host {
    host_path: String,
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

impl Host {
    pub fn new() -> Self {
        Self {
            host_path: "host".to_string(),
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { host_path: path }
    }

    /// Check if host is available
    pub fn is_available(&self) -> bool {
        Command::new(&self.host_path)
            .arg("-V")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Simple DNS lookup
    pub fn lookup(&self, domain: &str) -> Result<Vec<String>> {
        let output = Command::new(&self.host_path).arg(domain).output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let addresses = parse_host_output(&stdout);
            Ok(addresses)
        } else {
            Err(anyhow::anyhow!(
                "host lookup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// Lookup specific record type
    pub fn lookup_type(&self, domain: &str, record_type: RecordType) -> Result<Vec<String>> {
        let output = Command::new(&self.host_path)
            .arg("-t")
            .arg(record_type.as_str())
            .arg(domain)
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let records = parse_host_output(&stdout);
            Ok(records)
        } else {
            Err(anyhow::anyhow!(
                "host type lookup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// Reverse DNS lookup
    pub fn reverse_lookup(&self, ip: &str) -> Result<Vec<String>> {
        let output = Command::new(&self.host_path).arg(ip).output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let records = parse_host_output(&stdout);
            Ok(records)
        } else {
            Err(anyhow::anyhow!(
                "host reverse lookup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

fn parse_dig_output(output: &str, _record_type: RecordType) -> (Vec<String>, Option<u32>) {
    let mut records = Vec::new();
    let mut ttl = None;
    let mut in_answer = false;

    for line in output.lines() {
        if line.contains(";; ANSWER SECTION:") {
            in_answer = true;
            continue;
        }

        if in_answer && line.starts_with(';') {
            break;
        }

        if in_answer && !line.trim().is_empty() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                // Format: domain TTL class type data
                if ttl.is_none()
                    && let Ok(t) = parts[1].parse::<u32>()
                {
                    ttl = Some(t);
                }

                // Extract the data part (everything after type)
                let data = parts[4..].join(" ");
                records.push(data);
            }
        }
    }

    (records, ttl)
}

fn parse_host_output(output: &str) -> Vec<String> {
    let mut addresses = Vec::new();

    for line in output.lines() {
        // Example: "example.com has address 93.184.216.34"
        // Example: "example.com has IPv6 address 2606:2800:220:1:248:1893:25c8:1946"
        if line.contains("has address") || line.contains("has IPv6 address") {
            if let Some(addr) = line.split_whitespace().last() {
                addresses.push(addr.to_string());
            }
        } else if line.contains("mail is handled by") {
            // MX record: "example.com mail is handled by 10 mail.example.com."
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(mx) = parts.last() {
                addresses.push(mx.trim_end_matches('.').to_string());
            }
        }
    }

    addresses
}

/// Extended DNS lookup - try multiple methods
pub fn extended_lookup(domain: &str) -> Result<ExtendedDnsInfo> {
    let dig = Dig::new();
    let host = Host::new();

    let mut info = ExtendedDnsInfo {
        domain: domain.to_string(),
        a_records: Vec::new(),
        aaaa_records: Vec::new(),
        mx_records: Vec::new(),
        cname_records: Vec::new(),
        txt_records: Vec::new(),
        caa_records: Vec::new(),
        tlsa_records: Vec::new(),
    };

    // Try dig first (more detailed)
    if dig.is_available() {
        if let Ok(result) = dig.lookup(domain, RecordType::A) {
            info.a_records = result.records;
        }
        if let Ok(result) = dig.lookup(domain, RecordType::AAAA) {
            info.aaaa_records = result.records;
        }
        if let Ok(result) = dig.lookup(domain, RecordType::MX) {
            info.mx_records = result.records;
        }
        if let Ok(result) = dig.lookup(domain, RecordType::CNAME) {
            info.cname_records = result.records;
        }
        if let Ok(result) = dig.lookup(domain, RecordType::TXT) {
            info.txt_records = result.records;
        }
        if let Ok(result) = dig.lookup(domain, RecordType::CAA) {
            info.caa_records = result.records;
        }
        if let Ok(result) = dig.lookup(domain, RecordType::TLSA) {
            info.tlsa_records = result.records;
        }
    } else if host.is_available() {
        // Fallback to host
        if let Ok(records) = host.lookup(domain) {
            info.a_records = records;
        }
        if let Ok(records) = host.lookup_type(domain, RecordType::MX) {
            info.mx_records = records;
        }
    }

    Ok(info)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedDnsInfo {
    pub domain: String,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub caa_records: Vec<String>,
    pub tlsa_records: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_output() {
        let output = "example.com has address 93.184.216.34\nexample.com has IPv6 address 2606:2800:220:1:248:1893:25c8:1946";
        let addresses = parse_host_output(output);
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], "93.184.216.34");
    }

    #[test]
    fn test_record_type_as_str() {
        assert_eq!(RecordType::A.as_str(), "A");
        assert_eq!(RecordType::MX.as_str(), "MX");
        assert_eq!(RecordType::TLSA.as_str(), "TLSA");
    }
}
