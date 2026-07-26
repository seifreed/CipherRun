// Tests for alert channel trait defaults (no mocks).

use chrono::Utc;
use cipherrun::monitor::alerts::{Alert, AlertDetails, AlertType};
use cipherrun::monitor::detector::ChangeSeverity;

#[test]
fn test_alert_basic_construction() {
    let details = AlertDetails {
        certificate_serial: None,
        certificate_issuer: None,
        certificate_expiry: None,
        previous_serial: None,
        scan_time: Utc::now(),
    };

    let alert = Alert {
        hostname: "example.test".to_string(),
        alert_type: AlertType::ScanFailure {
            error: "oops".to_string(),
        },
        severity: ChangeSeverity::High,
        message: "test".to_string(),
        details,
        timestamp: Utc::now(),
    };

    assert_eq!(alert.hostname, "example.test");
    matches!(alert.alert_type, AlertType::ScanFailure { .. });
}
