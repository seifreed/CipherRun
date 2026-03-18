use crate::{Result, TlsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareScanIds {
    pub left: i64,
    pub right: i64,
}

impl CompareScanIds {
    pub fn parse(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 2 {
            return Err(TlsError::InvalidInput {
                message: "Expected format SCAN_ID_1:SCAN_ID_2".to_string(),
            });
        }

        let left = parts[0].parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid scan ID: {}", parts[0]),
        })?;
        let right = parts[1].parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid scan ID: {}", parts[1]),
        })?;

        Ok(Self { left, right })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPortDaysInput {
    pub hostname: String,
    pub port: u16,
    pub days: i64,
}

impl HostPortDaysInput {
    pub fn parse(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 3 {
            return Err(TlsError::InvalidInput {
                message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
            });
        }

        let hostname = parts[0].to_string();
        let port = parts[1].parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid port: {}", parts[1]),
        })?;
        let days = parts[2].parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid days: {}", parts[2]),
        })?;

        Ok(Self {
            hostname,
            port,
            days,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPortInput {
    pub hostname: String,
    pub port: u16,
}

impl HostPortInput {
    pub fn parse_with_default_port(raw: &str, default_port: u16) -> Self {
        let parts: Vec<&str> = raw.split(':').collect();
        let hostname = parts.first().unwrap_or(&"").to_string();
        let port = parts
            .get(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);

        Self { hostname, port }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compare_scan_ids() {
        let parsed = CompareScanIds::parse("1:2").expect("should parse");
        assert_eq!(parsed.left, 1);
        assert_eq!(parsed.right, 2);
    }

    #[test]
    fn rejects_invalid_compare_scan_ids() {
        assert!(CompareScanIds::parse("1").is_err());
    }

    #[test]
    fn parses_host_port_days() {
        let parsed = HostPortDaysInput::parse("example.com:443:7").expect("should parse");
        assert_eq!(parsed.hostname, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.days, 7);
    }

    #[test]
    fn parses_host_port_with_default_port() {
        let parsed = HostPortInput::parse_with_default_port("example.com", 443);
        assert_eq!(parsed.hostname, "example.com");
        assert_eq!(parsed.port, 443);
    }
}
