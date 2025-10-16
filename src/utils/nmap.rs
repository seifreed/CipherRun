// Nmap Greppable Format Parser
// Parses nmap -oG output format

use crate::Result;
use std::fs;

/// Nmap target from greppable output
#[derive(Debug, Clone)]
pub struct NmapTarget {
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
}

/// Nmap greppable format parser
pub struct NmapParser;

impl NmapParser {
    /// Parse nmap greppable output file
    pub fn parse_file(path: &str) -> Result<Vec<NmapTarget>> {
        let content = fs::read_to_string(path)?;
        Self::parse_content(&content)
    }

    /// Parse nmap greppable output content
    pub fn parse_content(content: &str) -> Result<Vec<NmapTarget>> {
        let mut targets = Vec::new();

        for line in content.lines() {
            // Skip comments and empty lines
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            // Parse Host line
            // Format: Host: IP (HOSTNAME) Status: STATE
            // Ports: PORT/STATE/PROTOCOL/OWNER/SERVICE/RPC/VERSION
            if line.starts_with("Host:")
                && let Some(parsed_targets) = Self::parse_host_line(line)
            {
                targets.extend(parsed_targets);
            }
        }

        Ok(targets)
    }

    /// Parse a single host line
    fn parse_host_line(line: &str) -> Option<Vec<NmapTarget>> {
        // Extract IP and hostname
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let ip = parts[1].to_string();
        let hostname = if parts.len() > 2 && parts[2].starts_with('(') {
            parts[2].trim_matches(|c| c == '(' || c == ')').to_string()
        } else {
            ip.clone()
        };

        // Find Ports: section
        let ports_section = line.split("Ports:").nth(1)?;

        // Parse each port entry
        let mut targets = Vec::new();
        for port_entry in ports_section.split(',') {
            let port_parts: Vec<&str> = port_entry.trim().split('/').collect();
            if port_parts.len() >= 3 {
                let port = port_parts[0].parse::<u16>().ok()?;
                let state = port_parts[1].to_string();
                let protocol = port_parts[2].to_string();

                // Only include open ports
                if state == "open" {
                    targets.push(NmapTarget {
                        hostname: hostname.clone(),
                        ip: ip.clone(),
                        port,
                        protocol,
                        state,
                    });
                }
            }
        }

        Some(targets)
    }

    /// Convert nmap targets to target strings for CipherRun
    pub fn to_target_strings(targets: &[NmapTarget]) -> Vec<String> {
        targets
            .iter()
            .filter(|t| t.protocol == "tcp") // Only TCP ports
            .map(|t| format!("{}:{}", t.hostname, t.port))
            .collect()
    }

    /// Filter targets by port (e.g., only HTTPS 443, SMTPS 465, etc.)
    pub fn filter_by_ports(targets: &[NmapTarget], ports: &[u16]) -> Vec<NmapTarget> {
        targets
            .iter()
            .filter(|t| ports.contains(&t.port))
            .cloned()
            .collect()
    }

    /// Get TLS/SSL ports from targets
    pub fn get_tls_ports(targets: &[NmapTarget]) -> Vec<NmapTarget> {
        // Common TLS/SSL ports
        let tls_ports = vec![
            443,  // HTTPS
            465,  // SMTPS
            587,  // SMTP STARTTLS
            993,  // IMAPS
            995,  // POP3S
            3306, // MySQL
            5432, // PostgreSQL
            636,  // LDAPS
            8443, // HTTPS alt
        ];

        Self::filter_by_ports(targets, &tls_ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_content() {
        let content = r#"# Nmap 7.80 scan
Host: 192.168.1.1 (example.com)	Status: Up
Host: 192.168.1.1 (example.com)	Ports: 443/open/tcp//https///	Ignored State: closed (999)
"#;

        let targets = NmapParser::parse_content(content).unwrap();
        assert!(!targets.is_empty());
    }

    #[test]
    fn test_to_target_strings() {
        let targets = vec![NmapTarget {
            hostname: "example.com".to_string(),
            ip: "192.168.1.1".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
        }];

        let strings = NmapParser::to_target_strings(&targets);
        assert_eq!(strings[0], "example.com:443");
    }

    #[test]
    fn test_filter_by_ports() {
        let targets = vec![
            NmapTarget {
                hostname: "example.com".to_string(),
                ip: "192.168.1.1".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
            },
            NmapTarget {
                hostname: "example.com".to_string(),
                ip: "192.168.1.1".to_string(),
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
            },
        ];

        let filtered = NmapParser::filter_by_ports(&targets, &[443]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 443);
    }
}
