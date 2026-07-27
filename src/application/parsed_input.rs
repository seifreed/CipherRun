use crate::security::input_validation::validate_hostname;
use crate::utils::network::{normalize_dns_hostname, split_target_host_port};
use crate::{Result, TlsError};

fn normalize_host_for_input(hostname: String) -> Result<String> {
    let hostname = normalize_dns_hostname(hostname);
    validate_hostname(&hostname).map_err(|error| TlsError::InvalidInput {
        message: error.to_string(),
    })?;
    let normalized_host = hostname.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host == "localhost"
        || normalized_host.ends_with(".local")
        || normalized_host.ends_with(".internal")
    {
        return Err(TlsError::InvalidInput {
            message: "Private/local hostnames are not allowed".to_string(),
        });
    }
    Ok(hostname)
}

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
            hostname: normalize_host_for_input(hostname)?,
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
            hostname: normalize_host_for_input(hostname)?,
            port: port.unwrap_or(default_port),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compare_scan_ids() {
        for input in ["1:2", " 1 : 2 "] {
            let parsed = CompareScanIds::parse(input).expect("should parse");
            assert_eq!(parsed.left, 1, "{input}");
            assert_eq!(parsed.right, 2, "{input}");
        }
    }

    #[test]
    fn rejects_invalid_compare_scan_ids() {
        for input in ["1", "1:2:3", "0:2", "1:0", "-1:2", "1:-2"] {
            assert!(CompareScanIds::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn parses_host_port_days() {
        for (input, hostname, port, days) in [
            ("example.com:443:7", "example.com", 443, 7),
            ("192.0.2.1:443:7", "192.0.2.1", 443, 7),
            ("example.com.:443:7", "example.com", 443, 7),
            (" example.com:443: 7 ", "example.com", 443, 7),
            ("[::1]:443:7", "::1", 443, 7),
        ] {
            let parsed = HostPortDaysInput::parse(input).expect("should parse");
            assert_eq!(parsed.hostname, hostname, "{input}");
            assert_eq!(parsed.port, port, "{input}");
            assert_eq!(parsed.days, days, "{input}");
        }
    }

    #[test]
    fn rejects_dotted_ip_literal_host_port_days() {
        assert!(HostPortDaysInput::parse("192.0.2.1.:443:7").is_err());
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
    fn rejects_invalid_host_port_days() {
        for input in [
            "example.com:443:0",
            "example.com:443:-7",
            &format!("example.com:443:{}", i64::MAX),
            "example.com:0:7",
            "::1:443:7",
            "127.1:443:7",
            "2130706433:443:7",
            "localhost:443:7",
            "service.local:443:7",
            "service.internal:443:7",
        ] {
            assert!(HostPortDaysInput::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn parses_host_port_with_default_port() {
        for (input, default_port, hostname, port) in [
            ("example.com", 443, "example.com", 443),
            ("192.0.2.1", 443, "192.0.2.1", 443),
            ("example.com.", 443, "example.com", 443),
            ("[::1]:8443", 443, "::1", 8443),
        ] {
            let parsed =
                HostPortInput::parse_with_default_port(input, default_port).expect("should parse");
            assert_eq!(parsed.hostname, hostname, "{input}");
            assert_eq!(parsed.port, port, "{input}");
        }
    }

    #[test]
    fn rejects_dotted_ip_literal_host_port_with_default_port() {
        assert!(HostPortInput::parse_with_default_port("192.0.2.1.", 443).is_err());
    }

    #[test]
    fn rejects_invalid_host_port_input() {
        for (input, default_port) in [
            ("127.1", 443),
            ("2130706433", 443),
            ("localhost", 443),
            ("service.local", 443),
            ("service.internal", 443),
            ("example.com:443:extra", 443),
            ("", 443),
            ("example.com:0", 443),
            ("example.com", 0),
        ] {
            assert!(
                HostPortInput::parse_with_default_port(input, default_port).is_err(),
                "{input}:{default_port}"
            );
        }
    }
}
