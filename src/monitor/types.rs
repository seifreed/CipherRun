// Core types for certificate monitoring

use crate::certificates::parser::CertificateInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

/// Alert thresholds for a monitored domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub expiry_30d: bool,
    pub expiry_14d: bool,
    pub expiry_7d: bool,
    pub expiry_1d: bool,
    pub on_change: bool,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            expiry_30d: true,
            expiry_14d: true,
            expiry_7d: true,
            expiry_1d: true,
            on_change: true,
        }
    }
}

/// Scan history record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub id: Option<i64>,
    pub hostname: String,
    pub port: u16,
    pub scan_time: DateTime<Utc>,
    pub status: ScanStatus,
    pub certificate_serial: Option<String>,
    pub certificate_issuer: Option<String>,
    pub certificate_expiry: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

/// Scan status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatus {
    Success,
    Failed,
    Timeout,
    ConnectionError,
    CertificateError,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Success => write!(f, "Success"),
            ScanStatus::Failed => write!(f, "Failed"),
            ScanStatus::Timeout => write!(f, "Timeout"),
            ScanStatus::ConnectionError => write!(f, "Connection Error"),
            ScanStatus::CertificateError => write!(f, "Certificate Error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_thresholds_default() {
        let thresholds = AlertThresholds::default();
        assert!(thresholds.expiry_30d);
        assert!(thresholds.expiry_14d);
        assert!(thresholds.expiry_7d);
        assert!(thresholds.expiry_1d);
        assert!(thresholds.on_change);
    }

    #[test]
    fn test_scan_status_display() {
        assert_eq!(ScanStatus::Success.to_string(), "Success");
        assert_eq!(ScanStatus::Failed.to_string(), "Failed");
        assert_eq!(ScanStatus::Timeout.to_string(), "Timeout");
    }

    #[test]
    fn test_monitored_domain_serialization() {
        let domain = MonitoredDomain {
            hostname: "example.com".to_string(),
            port: 443,
            enabled: true,
            interval_seconds: 3600,
            alert_thresholds: AlertThresholds::default(),
            last_scan: None,
            last_certificate: None,
        };

        let json = serde_json::to_string(&domain).unwrap();
        assert!(json.contains("example.com"));

        let deserialized: MonitoredDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hostname, "example.com");
        assert_eq!(deserialized.port, 443);
    }
}
