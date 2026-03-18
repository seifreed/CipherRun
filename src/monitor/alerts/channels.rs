// Alert Channel Trait

use crate::Result;
use crate::monitor::alerts::Alert;
use async_trait::async_trait;

/// Alert channel trait - implement this for custom alert channels
#[async_trait]
pub trait AlertChannel: Send + Sync {
    /// Send an alert through this channel
    async fn send_alert(&self, alert: &Alert) -> Result<()>;

    /// Get the channel name for logging
    fn channel_name(&self) -> &str;

    /// Test the channel connectivity (optional)
    async fn test_connection(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::alerts::{Alert, AlertDetails, AlertType};
    use crate::monitor::detector::ChangeSeverity;
    use chrono::Utc;

    struct DummyChannel;

    #[async_trait]
    impl AlertChannel for DummyChannel {
        async fn send_alert(&self, _alert: &Alert) -> Result<()> {
            Ok(())
        }

        fn channel_name(&self) -> &str {
            "dummy"
        }
    }

    #[tokio::test]
    async fn test_alert_channel_defaults() {
        let channel = DummyChannel;
        assert_eq!(channel.channel_name(), "dummy");
        channel.test_connection().await.expect("test connection ok");

        let alert = Alert {
            hostname: "example.com".to_string(),
            alert_type: AlertType::ScanFailure {
                error: "err".to_string(),
            },
            severity: ChangeSeverity::Low,
            message: "msg".to_string(),
            details: AlertDetails {
                certificate_serial: None,
                certificate_issuer: None,
                certificate_expiry: None,
                previous_serial: None,
                scan_time: Utc::now(),
            },
            timestamp: Utc::now(),
        };

        channel.send_alert(&alert).await.expect("send ok");
    }
}
