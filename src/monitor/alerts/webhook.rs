// Generic Webhook Alert Channel

use crate::Result;
use crate::monitor::alerts::{Alert, AlertChannel};
use crate::monitor::config::WebhookConfig;
use async_trait::async_trait;
use serde_json::json;

/// Generic webhook alert channel
pub struct WebhookChannel {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookChannel {
    /// Create new webhook channel
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Format alert as JSON for webhook
    fn format_payload(&self, alert: &Alert) -> serde_json::Value {
        json!({
            "source": "cipherrun-monitor",
            "version": "1.0",
            "alert": {
                "hostname": alert.hostname,
                "severity": alert.severity.to_string(),
                "message": alert.message,
                "timestamp": alert.timestamp.to_rfc3339(),
                "type": match &alert.alert_type {
                    crate::monitor::alerts::AlertType::CertificateChange { .. } => "certificate_change",
                    crate::monitor::alerts::AlertType::ExpiryWarning { .. } => "expiry_warning",
                    crate::monitor::alerts::AlertType::ValidationFailure { .. } => "validation_failure",
                    crate::monitor::alerts::AlertType::ScanFailure { .. } => "scan_failure",
                },
                "details": alert.details,
                "alert_type_data": alert.alert_type
            }
        })
    }
}

#[async_trait]
impl AlertChannel for WebhookChannel {
    async fn send_alert(&self, alert: &Alert) -> Result<()> {
        let payload = self.format_payload(alert);

        let mut request = self.client.post(&self.config.url).json(&payload);

        // Add custom headers
        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Webhook returned status {}: {}", status, body).into());
        }

        Ok(())
    }

    fn channel_name(&self) -> &str {
        "webhook"
    }

    async fn test_connection(&self) -> Result<()> {
        let test_payload = json!({
            "source": "cipherrun-monitor",
            "version": "1.0",
            "test": true,
            "message": "Test webhook from CipherRun monitoring"
        });

        let mut request = self.client.post(&self.config.url).json(&test_payload);

        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Webhook test failed: {}", response.status()).into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_config() -> WebhookConfig {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token123".to_string());

        WebhookConfig {
            enabled: true,
            url: "https://webhook.example.com/alerts".to_string(),
            headers,
        }
    }

    #[test]
    fn test_webhook_channel_new() {
        let config = create_test_config();
        let channel = WebhookChannel::new(config);
        assert_eq!(channel.channel_name(), "webhook");
    }

    #[test]
    fn test_format_payload() {
        let config = create_test_config();
        let channel = WebhookChannel::new(config);

        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        let payload = channel.format_payload(&alert);

        assert_eq!(payload["source"], "cipherrun-monitor");
        assert_eq!(payload["version"], "1.0");
        assert_eq!(payload["alert"]["hostname"], "example.com");
        assert_eq!(payload["alert"]["type"], "scan_failure");
    }
}
