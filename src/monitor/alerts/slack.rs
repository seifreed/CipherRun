// Slack Alert Channel - Webhook integration

use crate::monitor::alerts::{Alert, AlertChannel, AlertType};
use crate::monitor::config::SlackConfig;
use crate::monitor::detector::ChangeSeverity;
use crate::Result;
use async_trait::async_trait;
use serde_json::json;

/// Slack alert channel
pub struct SlackChannel {
    config: SlackConfig,
    client: reqwest::Client,
}

impl SlackChannel {
    /// Create new Slack channel
    pub fn new(config: SlackConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Format alert as Slack message
    fn format_message(&self, alert: &Alert) -> serde_json::Value {
        let color = match alert.severity {
            ChangeSeverity::Critical => "#dc3545",
            ChangeSeverity::High => "#fd7e14",
            ChangeSeverity::Medium => "#ffc107",
            ChangeSeverity::Low => "#0dcaf0",
            ChangeSeverity::Info => "#6c757d",
        };

        let emoji = match alert.severity {
            ChangeSeverity::Critical => ":rotating_light:",
            ChangeSeverity::High => ":warning:",
            ChangeSeverity::Medium => ":large_orange_diamond:",
            ChangeSeverity::Low => ":information_source:",
            ChangeSeverity::Info => ":white_check_mark:",
        };

        let mut fields = vec![
            json!({
                "title": "Hostname",
                "value": alert.hostname,
                "short": true
            }),
            json!({
                "title": "Severity",
                "value": alert.severity.to_string().to_uppercase(),
                "short": true
            }),
            json!({
                "title": "Time",
                "value": alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                "short": true
            }),
        ];

        // Add alert-type specific fields
        match &alert.alert_type {
            AlertType::CertificateChange { changes } => {
                fields.push(json!({
                    "title": "Changes",
                    "value": format!("{} changes detected", changes.len()),
                    "short": true
                }));

                let changes_text = changes
                    .iter()
                    .map(|c| format!("• {:?}: {}", c.change_type, c.description))
                    .collect::<Vec<_>>()
                    .join("\n");

                fields.push(json!({
                    "title": "Details",
                    "value": changes_text,
                    "short": false
                }));
            }
            AlertType::ExpiryWarning { days_remaining } => {
                fields.push(json!({
                    "title": "Days Remaining",
                    "value": format!("{} days", days_remaining),
                    "short": true
                }));
            }
            AlertType::ValidationFailure { reason } => {
                fields.push(json!({
                    "title": "Reason",
                    "value": reason,
                    "short": false
                }));
            }
            AlertType::ScanFailure { error } => {
                fields.push(json!({
                    "title": "Error",
                    "value": error,
                    "short": false
                }));
            }
        }

        // Add certificate details if available
        if let Some(ref serial) = alert.details.certificate_serial {
            fields.push(json!({
                "title": "Certificate Serial",
                "value": serial,
                "short": true
            }));
        }

        if let Some(ref issuer) = alert.details.certificate_issuer {
            fields.push(json!({
                "title": "Certificate Issuer",
                "value": issuer,
                "short": true
            }));
        }

        if let Some(ref expiry) = alert.details.certificate_expiry {
            fields.push(json!({
                "title": "Certificate Expiry",
                "value": expiry,
                "short": true
            }));
        }

        json!({
            "username": "CipherRun Monitor",
            "icon_emoji": emoji,
            "attachments": [
                {
                    "color": color,
                    "title": format!("{} Alert", alert.severity.to_string().to_uppercase()),
                    "text": alert.message,
                    "fields": fields,
                    "footer": "CipherRun Certificate Monitoring",
                    "ts": alert.timestamp.timestamp()
                }
            ]
        })
    }
}

#[async_trait]
impl AlertChannel for SlackChannel {
    async fn send_alert(&self, alert: &Alert) -> Result<()> {
        let message = self.format_message(alert);

        let response = self
            .client
            .post(&self.config.webhook_url)
            .json(&message)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow::anyhow!(
                "Slack webhook returned status {}: {}",
                status,
                body
            )
            .into());
        }

        Ok(())
    }

    fn channel_name(&self) -> &str {
        "slack"
    }

    async fn test_connection(&self) -> Result<()> {
        let test_message = json!({
            "text": "Test message from CipherRun monitoring - connection successful!"
        });

        let response = self
            .client
            .post(&self.config.webhook_url)
            .json(&test_message)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(
                anyhow::anyhow!("Slack webhook test failed: {}", response.status()).into(),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> SlackConfig {
        SlackConfig {
            enabled: true,
            webhook_url: "https://hooks.slack.com/services/TEST/WEBHOOK/URL".to_string(),
        }
    }

    #[test]
    fn test_slack_channel_new() {
        let config = create_test_config();
        let channel = SlackChannel::new(config);
        assert_eq!(channel.channel_name(), "slack");
    }

    #[test]
    fn test_format_message() {
        let config = create_test_config();
        let channel = SlackChannel::new(config);

        let alert = Alert::scan_failure(
            "example.com".to_string(),
            "Connection refused".to_string(),
        );

        let message = channel.format_message(&alert);

        assert!(message["attachments"].is_array());
        assert!(message["attachments"][0]["title"]
            .as_str()
            .unwrap()
            .contains("Alert"));
        assert!(message["attachments"][0]["text"]
            .as_str()
            .unwrap()
            .contains("example.com"));
    }

    #[test]
    fn test_format_message_with_changes() {
        use crate::monitor::detector::{ChangeEvent, ChangeType};
        use crate::monitor::alerts::AlertDetails;
        use chrono::Utc;

        let config = create_test_config();
        let channel = SlackChannel::new(config);

        let changes = vec![ChangeEvent {
            change_type: ChangeType::Renewal,
            severity: ChangeSeverity::Info,
            description: "Certificate renewed".to_string(),
            previous_value: Some("old".to_string()),
            current_value: Some("new".to_string()),
            detected_at: Utc::now(),
        }];

        let alert = Alert::certificate_change(
            "example.com".to_string(),
            changes,
            AlertDetails {
                certificate_serial: Some("123456".to_string()),
                certificate_issuer: Some("Let's Encrypt".to_string()),
                certificate_expiry: Some("2025-01-01".to_string()),
                previous_serial: None,
                scan_time: Utc::now(),
            },
        );

        let message = channel.format_message(&alert);

        // Verify fields are present
        let fields = &message["attachments"][0]["fields"];
        assert!(fields.is_array());
        assert!(!fields.as_array().unwrap().is_empty());
    }
}
