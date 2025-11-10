// ASN and CIDR Input Support Module
// Supports ASN (Autonomous System Number) and CIDR notation as input

use crate::error::TlsError;
use crate::Result;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// ASN and CIDR parser
pub struct AsnCidrParser;

impl AsnCidrParser {
    /// Parse ASN and expand to IP ranges
    /// Format: AS1449 or 1449
    pub async fn expand_asn(asn: &str) -> Result<Vec<IpNetwork>> {
        let asn_number = Self::parse_asn_number(asn)?;

        // Query BGP tables via RIPEstat API
        let prefixes = Self::query_ripestat_api(asn_number).await?;

        Ok(prefixes)
    }

    /// Parse ASN number from string (supports "AS1449" or "1449")
    fn parse_asn_number(asn: &str) -> Result<u32> {
        let asn_str = asn.trim();

        // Remove "AS" prefix if present
        let num_str = if asn_str.to_uppercase().starts_with("AS") {
            &asn_str[2..]
        } else {
            asn_str
        };

        num_str.parse::<u32>().map_err(|e| TlsError::InvalidInput {
            message: format!("Invalid ASN format '{}': {}", asn, e),
        })
    }

    /// Query RIPEstat API for ASN prefixes
    async fn query_ripestat_api(asn: u32) -> Result<Vec<IpNetwork>> {
        let url = format!(
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}",
            asn
        );

        let client = reqwest::Client::builder()
            .user_agent("CipherRun/1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| TlsError::ConfigError {
                message: format!("Failed to create HTTP client: {}", e),
            })?;

        let response = client.get(&url).send().await.map_err(|e| {
            TlsError::HttpError {
                status: 0,
                details: format!("RIPEstat API request failed: {}", e),
            }
        })?;

        if !response.status().is_success() {
            return Err(TlsError::HttpError {
                status: response.status().as_u16(),
                details: format!("RIPEstat API returned error: {}", response.status()),
            });
        }

        let json: serde_json::Value = response.json().await.map_err(|e| TlsError::ParseError {
            message: format!("Failed to parse RIPEstat response: {}", e),
        })?;

        // Parse prefixes from JSON response
        let mut prefixes = Vec::new();

        if let Some(data) = json.get("data") {
            if let Some(prefixes_array) = data.get("prefixes").and_then(|p| p.as_array()) {
                for prefix_obj in prefixes_array {
                    if let Some(prefix_str) = prefix_obj.get("prefix").and_then(|p| p.as_str()) {
                        if let Ok(network) = prefix_str.parse::<IpNetwork>() {
                            prefixes.push(network);
                        }
                    }
                }
            }
        }

        if prefixes.is_empty() {
            return Err(TlsError::InvalidInput {
                message: format!("No prefixes found for AS{}", asn),
            });
        }

        Ok(prefixes)
    }

    /// Expand CIDR notation to individual IPs
    /// For large ranges, returns the network object instead of all IPs
    pub fn expand_cidr(cidr: &str) -> Result<CidrExpansion> {
        let network = cidr.parse::<IpNetwork>().map_err(|e| TlsError::InvalidInput {
            message: format!("Invalid CIDR format '{}': {}", cidr, e),
        })?;

        let total_ips = Self::calculate_ip_count(&network);

        // For large networks, don't expand all IPs (memory-efficient)
        const MAX_EXPAND: u64 = 1024; // Expand up to /22 for IPv4, /118 for IPv6

        if total_ips <= MAX_EXPAND {
            // Small network - expand all IPs
            let ips: Vec<IpAddr> = network.iter().collect();
            Ok(CidrExpansion::FullList {
                network,
                ips,
                total: total_ips,
            })
        } else {
            // Large network - return iterator-based expansion
            Ok(CidrExpansion::Network {
                network,
                total: total_ips,
            })
        }
    }

    /// Calculate total IP count for a network
    fn calculate_ip_count(network: &IpNetwork) -> u64 {
        match network {
            IpNetwork::V4(v4) => {
                let prefix_len = v4.prefix();
                if prefix_len >= 32 {
                    1
                } else {
                    2u64.pow(32 - prefix_len as u32)
                }
            }
            IpNetwork::V6(v6) => {
                let prefix_len = v6.prefix();
                if prefix_len >= 128 {
                    1
                } else if prefix_len <= 64 {
                    // For large IPv6 networks, return a large number
                    u64::MAX
                } else {
                    2u64.pow(128 - prefix_len as u32).min(u64::MAX)
                }
            }
        }
    }

    /// Detect input type from string
    pub fn parse_input(input: &str) -> InputType {
        let input = input.trim();

        // Check for ASN format
        if input.to_uppercase().starts_with("AS") || input.parse::<u32>().is_ok() {
            // Verify it's a valid ASN number
            if let Ok(asn_num) = Self::parse_asn_number(input) {
                if asn_num > 0 && asn_num < 4_294_967_295 {
                    return InputType::Asn(input.to_string());
                }
            }
        }

        // Check for CIDR notation
        if input.contains('/') {
            if input.parse::<IpNetwork>().is_ok() {
                return InputType::Cidr(input.to_string());
            }
        }

        // Check for IP address
        if let Ok(ip) = input.parse::<IpAddr>() {
            return InputType::Ip(ip);
        }

        // Default to hostname
        InputType::Hostname(input.to_string())
    }

    /// Expand multiple inputs (supports mixed types)
    pub async fn expand_inputs(inputs: Vec<String>) -> Result<Vec<ExpandedInput>> {
        let mut results = Vec::new();

        for input in inputs {
            let input_type = Self::parse_input(&input);
            let expanded = Self::expand_input_type(input_type).await?;
            results.push(expanded);
        }

        Ok(results)
    }

    /// Expand a single input type
    async fn expand_input_type(input_type: InputType) -> Result<ExpandedInput> {
        match input_type {
            InputType::Asn(asn) => {
                let networks = Self::expand_asn(&asn).await?;
                Ok(ExpandedInput::Asn {
                    asn: asn.clone(),
                    networks,
                })
            }
            InputType::Cidr(cidr) => {
                let expansion = Self::expand_cidr(&cidr)?;
                Ok(ExpandedInput::Cidr {
                    cidr: cidr.clone(),
                    expansion,
                })
            }
            InputType::Ip(ip) => Ok(ExpandedInput::Ip { ip }),
            InputType::Hostname(hostname) => Ok(ExpandedInput::Hostname { hostname }),
        }
    }
}

/// Input type classification
#[derive(Debug, Clone)]
pub enum InputType {
    Asn(String),
    Cidr(String),
    Ip(IpAddr),
    Hostname(String),
}

/// CIDR expansion result
#[derive(Debug, Clone)]
pub enum CidrExpansion {
    /// Small network with all IPs expanded
    FullList {
        network: IpNetwork,
        ips: Vec<IpAddr>,
        total: u64,
    },
    /// Large network (use iterator for memory efficiency)
    Network { network: IpNetwork, total: u64 },
}

impl CidrExpansion {
    /// Get iterator over all IPs in the network
    pub fn iter(&self) -> Box<dyn Iterator<Item = IpAddr> + '_> {
        match self {
            CidrExpansion::FullList { ips, .. } => Box::new(ips.iter().copied()),
            CidrExpansion::Network { network, .. } => Box::new(network.iter()),
        }
    }

    /// Get total IP count
    pub fn total_ips(&self) -> u64 {
        match self {
            CidrExpansion::FullList { total, .. } => *total,
            CidrExpansion::Network { total, .. } => *total,
        }
    }

    /// Get network
    pub fn network(&self) -> &IpNetwork {
        match self {
            CidrExpansion::FullList { network, .. } => network,
            CidrExpansion::Network { network, .. } => network,
        }
    }
}

/// Expanded input (after processing)
#[derive(Debug, Clone)]
pub enum ExpandedInput {
    Asn {
        asn: String,
        networks: Vec<IpNetwork>,
    },
    Cidr {
        cidr: String,
        expansion: CidrExpansion,
    },
    Ip {
        ip: IpAddr,
    },
    Hostname {
        hostname: String,
    },
}

impl ExpandedInput {
    /// Get total target count
    pub fn target_count(&self) -> u64 {
        match self {
            ExpandedInput::Asn { networks, .. } => {
                networks.iter().map(|n| Self::network_size(n)).sum()
            }
            ExpandedInput::Cidr { expansion, .. } => expansion.total_ips(),
            ExpandedInput::Ip { .. } => 1,
            ExpandedInput::Hostname { .. } => 1,
        }
    }

    /// Calculate network size
    fn network_size(network: &IpNetwork) -> u64 {
        match network {
            IpNetwork::V4(v4) => {
                let prefix = v4.prefix();
                if prefix >= 32 {
                    1
                } else {
                    2u64.pow(32 - prefix as u32)
                }
            }
            IpNetwork::V6(v6) => {
                let prefix = v6.prefix();
                if prefix >= 128 {
                    1
                } else if prefix <= 64 {
                    u64::MAX
                } else {
                    2u64.pow(128 - prefix as u32).min(u64::MAX)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_asn_number() {
        assert_eq!(AsnCidrParser::parse_asn_number("1449").unwrap(), 1449);
        assert_eq!(AsnCidrParser::parse_asn_number("AS1449").unwrap(), 1449);
        assert_eq!(AsnCidrParser::parse_asn_number("as1449").unwrap(), 1449);

        assert!(AsnCidrParser::parse_asn_number("invalid").is_err());
        assert!(AsnCidrParser::parse_asn_number("AS").is_err());
    }

    #[test]
    fn test_parse_input_asn() {
        match AsnCidrParser::parse_input("AS1449") {
            InputType::Asn(asn) => assert_eq!(asn, "AS1449"),
            _ => panic!("Expected ASN input type"),
        }

        match AsnCidrParser::parse_input("1449") {
            InputType::Asn(asn) => assert_eq!(asn, "1449"),
            _ => panic!("Expected ASN input type"),
        }
    }

    #[test]
    fn test_parse_input_cidr() {
        match AsnCidrParser::parse_input("192.0.2.0/24") {
            InputType::Cidr(cidr) => assert_eq!(cidr, "192.0.2.0/24"),
            _ => panic!("Expected CIDR input type"),
        }

        match AsnCidrParser::parse_input("2001:db8::/32") {
            InputType::Cidr(cidr) => assert_eq!(cidr, "2001:db8::/32"),
            _ => panic!("Expected CIDR input type"),
        }
    }

    #[test]
    fn test_parse_input_ip() {
        match AsnCidrParser::parse_input("192.0.2.1") {
            InputType::Ip(ip) => assert_eq!(ip.to_string(), "192.0.2.1"),
            _ => panic!("Expected IP input type"),
        }

        match AsnCidrParser::parse_input("2001:db8::1") {
            InputType::Ip(ip) => assert!(ip.to_string().contains("2001:db8")),
            _ => panic!("Expected IP input type"),
        }
    }

    #[test]
    fn test_parse_input_hostname() {
        match AsnCidrParser::parse_input("example.com") {
            InputType::Hostname(hostname) => assert_eq!(hostname, "example.com"),
            _ => panic!("Expected Hostname input type"),
        }
    }

    #[test]
    fn test_expand_cidr_small() {
        let expansion = AsnCidrParser::expand_cidr("192.0.2.0/30").unwrap();

        match expansion {
            CidrExpansion::FullList { ips, total, .. } => {
                assert_eq!(total, 4);
                assert_eq!(ips.len(), 4);
            }
            _ => panic!("Expected FullList for small network"),
        }
    }

    #[test]
    fn test_expand_cidr_large() {
        let expansion = AsnCidrParser::expand_cidr("10.0.0.0/8").unwrap();

        match expansion {
            CidrExpansion::Network { total, .. } => {
                assert_eq!(total, 16777216); // 2^24
            }
            _ => panic!("Expected Network for large network"),
        }
    }

    #[test]
    fn test_cidr_expansion_iter() {
        let expansion = AsnCidrParser::expand_cidr("192.0.2.0/30").unwrap();
        let ips: Vec<IpAddr> = expansion.iter().collect();

        assert_eq!(ips.len(), 4);
        assert_eq!(ips[0].to_string(), "192.0.2.0");
        assert_eq!(ips[3].to_string(), "192.0.2.3");
    }

    // Note: ASN API tests require network access and are integration tests
}
