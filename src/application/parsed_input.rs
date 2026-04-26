use crate::utils::network::split_target_host_port;
use crate::{Result, TlsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareScanIds {
    pub left: i64,
    pub right: i64,
}

impl CompareScanIds {
    pub fn parse(raw: &str) -> Result<Self> {
        let Some((left_raw, right_raw)) = raw.split_once(':') else {
            return Err(TlsError::InvalidInput {
                message: "Expected format SCAN_ID_1:SCAN_ID_2".to_string(),
            });
        };
        if right_raw.contains(':') {
            return Err(TlsError::InvalidInput {
                message: "Expected format SCAN_ID_1:SCAN_ID_2".to_string(),
            });
        }

        let left = left_raw.parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid scan ID: {}", left_raw),
        })?;
        let right = right_raw.parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid scan ID: {}", right_raw),
        })?;

        if left <= 0 {
            return Err(TlsError::InvalidInput {
                message: format!("Scan ID must be positive: {}", left),
            });
        }
        if right <= 0 {
            return Err(TlsError::InvalidInput {
                message: format!("Scan ID must be positive: {}", right),
            });
        }

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
        if raw.matches(':').count() < 2 {
            return Err(TlsError::InvalidInput {
                message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
            });
        }

        let (host_port, days_str) = raw.rsplit_once(':').ok_or_else(|| TlsError::InvalidInput {
            message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
        })?;

        let days = days_str.parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid days: {}", days_str),
        })?;
        if days <= 0 {
            return Err(TlsError::InvalidInput {
                message: format!("Days must be positive: {}", days),
            });
        }

        let (hostname, port) =
            split_target_host_port(host_port).map_err(|e| TlsError::InvalidInput {
                message: e.to_string(),
            })?;

        let Some(port) = port else {
            return Err(TlsError::InvalidInput {
                message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
            });
        };

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
    pub fn parse_with_default_port(raw: &str, default_port: u16) -> Result<Self> {
        let (hostname, port) = split_target_host_port(raw).map_err(|e| TlsError::InvalidInput {
            message: e.to_string(),
        })?;

        Ok(Self {
            hostname,
            port: port.unwrap_or(default_port),
        })
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
        assert!(CompareScanIds::parse("1:2:3").is_err());
    }

    #[test]
    fn rejects_non_positive_compare_scan_ids() {
        assert!(CompareScanIds::parse("0:2").is_err());
        assert!(CompareScanIds::parse("1:0").is_err());
        assert!(CompareScanIds::parse("-1:2").is_err());
        assert!(CompareScanIds::parse("1:-2").is_err());
    }

    #[test]
    fn parses_host_port_days() {
        let parsed = HostPortDaysInput::parse("example.com:443:7").expect("should parse");
        assert_eq!(parsed.hostname, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.days, 7);
    }

    #[test]
    fn rejects_non_positive_host_port_days() {
        assert!(HostPortDaysInput::parse("example.com:443:0").is_err());
        assert!(HostPortDaysInput::parse("example.com:443:-7").is_err());
    }

    #[test]
    fn parses_host_port_days_with_bracketed_ipv6() {
        let parsed = HostPortDaysInput::parse("[::1]:443:7").expect("should parse");
        assert_eq!(parsed.hostname, "::1");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.days, 7);
    }

    #[test]
    fn rejects_host_port_days_with_ipv6_without_brackets() {
        assert!(HostPortDaysInput::parse("::1:443:7").is_err());
    }

    #[test]
    fn parses_host_port_with_default_port() {
        let parsed =
            HostPortInput::parse_with_default_port("example.com", 443).expect("should parse");
        assert_eq!(parsed.hostname, "example.com");
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn parses_bracketed_ipv6_host_port_with_default_port() {
        let parsed =
            HostPortInput::parse_with_default_port("[::1]:8443", 443).expect("should parse");
        assert_eq!(parsed.hostname, "::1");
        assert_eq!(parsed.port, 8443);
    }

    #[test]
    fn rejects_malformed_host_port_input() {
        assert!(HostPortInput::parse_with_default_port("example.com:443:extra", 443).is_err());
    }
}
