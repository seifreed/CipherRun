use crate::utils::network::{normalize_dns_hostname, split_target_host_port};
use crate::{Result, TlsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareScanIds {
    pub left: i64,
    pub right: i64,
}

impl CompareScanIds {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
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

        let left_raw = left_raw.trim();
        let right_raw = right_raw.trim();
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
        let raw = raw.trim();
        if raw.matches(':').count() < 2 {
            return Err(TlsError::InvalidInput {
                message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
            });
        }

        let (host_port, days_str) = raw.rsplit_once(':').ok_or_else(|| TlsError::InvalidInput {
            message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
        })?;
        if host_port.contains("://") {
            let url = url::Url::parse(host_port).map_err(|_| TlsError::InvalidInput {
                message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
            })?;
            if url.port().is_none() {
                return Err(TlsError::InvalidInput {
                    message: "Expected format HOSTNAME:PORT:DAYS".to_string(),
                });
            }
        }

        let days_str = days_str.trim();
        let days = days_str.parse().map_err(|_| TlsError::InvalidInput {
            message: format!("Invalid days: {}", days_str),
        })?;
        if days <= 0 {
            return Err(TlsError::InvalidInput {
                message: format!("Days must be positive: {}", days),
            });
        }
        if chrono::Duration::try_days(days).is_none() {
            return Err(TlsError::InvalidInput {
                message: format!("Days value is too large: {}", days),
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
            hostname: normalize_dns_hostname(hostname),
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
        if default_port == 0 {
            return Err(TlsError::InvalidInput {
                message: "Default port must be between 1 and 65535".to_string(),
            });
        }

        let (hostname, port) = split_target_host_port(raw).map_err(|e| TlsError::InvalidInput {
            message: e.to_string(),
        })?;

        Ok(Self {
            hostname: normalize_dns_hostname(hostname),
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
    fn trims_compare_scan_ids() {
        let parsed = CompareScanIds::parse(" 1 : 2 ").expect("should parse");
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
    fn host_port_days_normalizes_rooted_fqdn() {
        let parsed = HostPortDaysInput::parse("example.com.:443:7").expect("should parse");
        assert_eq!(parsed.hostname, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.days, 7);
    }

    #[test]
    fn rejects_host_port_days_url_without_explicit_port() {
        assert!(HostPortDaysInput::parse("https://example.com:7").is_err());
    }

    #[test]
    fn rejects_host_port_days_url_path_colon_without_authority_port() {
        assert!(HostPortDaysInput::parse("https://example.com/path:443:7").is_err());
    }

    #[test]
    fn trims_host_port_days() {
        let parsed =
            HostPortDaysInput::parse(" example.com:443: 7 ").expect("should parse trimmed input");
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
    fn rejects_oversized_host_port_days() {
        assert!(HostPortDaysInput::parse(&format!("example.com:443:{}", i64::MAX)).is_err());
    }

    #[test]
    fn rejects_zero_port_host_port_days() {
        assert!(HostPortDaysInput::parse("example.com:0:7").is_err());
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
    fn host_port_input_normalizes_rooted_fqdn() {
        let parsed =
            HostPortInput::parse_with_default_port("example.com.", 443).expect("should parse");
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

    #[test]
    fn rejects_empty_host_port_input() {
        assert!(HostPortInput::parse_with_default_port("", 443).is_err());
    }

    #[test]
    fn rejects_zero_port_host_port_input() {
        assert!(HostPortInput::parse_with_default_port("example.com:0", 443).is_err());
    }

    #[test]
    fn rejects_zero_default_port_host_port_input() {
        assert!(HostPortInput::parse_with_default_port("example.com", 0).is_err());
    }
}
