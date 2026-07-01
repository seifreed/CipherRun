// Generic Webhook Alert Channel

use crate::Result;
use crate::error::TlsError;
use crate::monitor::alerts::{Alert, AlertChannel};
use crate::monitor::config::WebhookConfig;
use async_trait::async_trait;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::json;

/// Generic webhook alert channel
pub struct WebhookChannel {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookChannel {
    /// Create new webhook channel
    pub fn new(config: WebhookConfig) -> Result<Self> {
        let url = reqwest::Url::parse(&config.url).map_err(|error| TlsError::ConfigError {
            message: format!("Invalid webhook url: {error}"),
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(TlsError::ConfigError {
                message: "Invalid webhook url: scheme must be http or https".to_string(),
            });
        }
        if matches!(url.port(), Some(0)) {
            return Err(TlsError::ConfigError {
                message: "Invalid webhook url: port must be between 1 and 65535".to_string(),
            });
        }
        for (name, value) in &config.headers {
            HeaderName::from_bytes(name.as_bytes()).map_err(|error| TlsError::ConfigError {
                message: format!("Invalid webhook header name '{name}': {error}"),
            })?;
            HeaderValue::from_str(value).map_err(|error| TlsError::ConfigError {
                message: format!("Invalid webhook header value for '{name}': {error}"),
            })?;
        }

        Ok(Self {
            config,
            client: reqwest::Client::new(),
        })
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
            let body = super::alert_error_body(response, "Webhook error response").await?;
            return Err(TlsError::HttpError {
                status: status.as_u16(),
                details: format!("Webhook error: {body}"),
            });
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
            return Err(TlsError::HttpError {
                status: response.status().as_u16(),
                details: "Webhook test failed".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::alerts::AlertChannel;
    use axum::{Router, http::StatusCode, routing::post};
    use std::collections::HashMap;
    use tokio::net::TcpListener;

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
        let channel = WebhookChannel::new(config).expect("test assertion should succeed");
        assert_eq!(channel.channel_name(), "webhook");
    }

    #[test]
    fn test_format_payload() {
        let config = create_test_config();
        let channel = WebhookChannel::new(config).expect("test assertion should succeed");

        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        let payload = channel.format_payload(&alert);

        assert_eq!(payload["source"], "cipherrun-monitor");
        assert_eq!(payload["version"], "1.0");
        assert_eq!(payload["alert"]["hostname"], "example.com");
        assert_eq!(payload["alert"]["type"], "scan_failure");
    }

    #[tokio::test]
    async fn test_send_alert_preserves_error_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");
        let app = Router::new().route(
            "/alerts",
            post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "delivery failed") }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let channel = WebhookChannel::new(WebhookConfig {
            enabled: true,
            url: format!("http://{addr}/alerts"),
            headers: HashMap::new(),
        })
        .expect("test assertion should succeed");
        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        let err = channel
            .send_alert(&alert)
            .await
            .expect_err("webhook error should fail");

        assert!(err.to_string().contains("delivery failed"));
    }

    #[tokio::test]
    async fn test_send_alert_caps_error_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");
        let app = Router::new().route(
            "/alerts",
            post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "x".repeat(70 * 1024)) }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let channel = WebhookChannel::new(WebhookConfig {
            enabled: true,
            url: format!("http://{addr}/alerts"),
            headers: HashMap::new(),
        })
        .expect("test assertion should succeed");
        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        let err = channel
            .send_alert(&alert)
            .await
            .expect_err("oversized webhook error should fail");

        assert!(
            err.to_string()
                .contains("Webhook error response response too large")
        );
    }

    #[test]
    fn test_webhook_channel_rejects_invalid_header() {
        let mut headers = HashMap::new();
        headers.insert("bad header".to_string(), "value".to_string());

        let result = WebhookChannel::new(WebhookConfig {
            enabled: true,
            url: "https://webhook.example.com/alerts".to_string(),
            headers,
        });
        let err = match result {
            Ok(_) => panic!("invalid header should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Invalid webhook header name"));
    }
}
