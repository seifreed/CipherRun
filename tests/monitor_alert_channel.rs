// Tests for alert channel trait defaults (no mocks).

use chrono::Utc;
use cipherrun::monitor::alerts::{Alert, AlertChannel, AlertDetails, AlertType};
use cipherrun::monitor::detector::ChangeSeverity;

struct DummyChannel;

#[async_trait::async_trait]
impl AlertChannel for DummyChannel {
    async fn send_alert(&self, _alert: &Alert) -> cipherrun::Result<()> {
        Ok(())
    }

    fn channel_name(&self) -> &str {
        "dummy"
    }
}

#[tokio::test]
async fn test_alert_channel_default_connection() {
    let channel = DummyChannel;
    channel
        .test_connection()
        .await
        .expect("test assertion should succeed");
    assert_eq!(channel.channel_name(), "dummy");
}

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
