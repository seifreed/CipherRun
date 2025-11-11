// Microsoft Teams Alert Channel - Webhook integration

use crate::Result;
use crate::monitor::alerts::{Alert, AlertChannel, AlertType};
use crate::monitor::config::TeamsConfig;
use crate::monitor::detector::ChangeSeverity;
use async_trait::async_trait;
use serde_json::json;

/// Microsoft Teams alert channel
pub struct TeamsChannel {
    config: TeamsConfig,
    client: reqwest::Client,
}

impl TeamsChannel {
    /// Create new Teams channel
    pub fn new(config: TeamsConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Format alert as Teams Adaptive Card message
    fn format_message(&self, alert: &Alert) -> serde_json::Value {
        let theme_color = match alert.severity {
            ChangeSeverity::Critical => "attention",
            ChangeSeverity::High => "warning",
            ChangeSeverity::Medium => "accent",
            ChangeSeverity::Low => "good",
            ChangeSeverity::Info => "default",
        };

        let mut facts = vec![
            json!({"title": "Hostname", "value": alert.hostname}),
            json!({"title": "Severity", "value": alert.severity.to_string().to_uppercase()}),
            json!({"title": "Time", "value": alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()}),
        ];

        // Add alert-type specific facts
        match &alert.alert_type {
            AlertType::CertificateChange { changes } => {
                facts.push(json!({"title": "Changes", "value": format!("{} changes detected", changes.len())}));

                let changes_text = changes
                    .iter()
                    .map(|c| format!("• {:?}: {}", c.change_type, c.description))
                    .collect::<Vec<_>>()
                    .join("\n\n");

                facts.push(json!({"title": "Details", "value": changes_text}));
            }
            AlertType::ExpiryWarning { days_remaining } => {
                facts.push(
                    json!({"title": "Days Remaining", "value": format!("{} days", days_remaining)}),
                );
            }
            AlertType::ValidationFailure { reason } => {
                facts.push(json!({"title": "Reason", "value": reason}));
            }
            AlertType::ScanFailure { error } => {
                facts.push(json!({"title": "Error", "value": error}));
            }
        }

        // Add certificate details if available
        if let Some(ref serial) = alert.details.certificate_serial {
            facts.push(json!({"title": "Certificate Serial", "value": serial}));
        }

        if let Some(ref issuer) = alert.details.certificate_issuer {
            facts.push(json!({"title": "Certificate Issuer", "value": issuer}));
        }

        if let Some(ref expiry) = alert.details.certificate_expiry {
            facts.push(json!({"title": "Certificate Expiry", "value": expiry}));
        }

        json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": alert.message,
            "themeColor": theme_color,
            "title": format!("{} Alert - CipherRun Monitor", alert.severity.to_string().to_uppercase()),
            "sections": [
                {
                    "activityTitle": alert.message,
                    "facts": facts,
                    "markdown": true
                }
            ]
        })
    }
}

#[async_trait]
impl AlertChannel for TeamsChannel {
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
            return Err(
                anyhow::anyhow!("Teams webhook returned status {}: {}", status, body).into(),
            );
        }

        Ok(())
    }

    fn channel_name(&self) -> &str {
        "teams"
    }

    async fn test_connection(&self) -> Result<()> {
        let test_message = json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "Test Alert",
            "title": "CipherRun Monitor - Connection Test",
            "text": "Test message from CipherRun monitoring - connection successful!"
        });

        let response = self
            .client
            .post(&self.config.webhook_url)
            .json(&test_message)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Teams webhook test failed: {}", response.status()).into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> TeamsConfig {
        TeamsConfig {
            enabled: true,
            webhook_url: "https://outlook.office.com/webhook/TEST".to_string(),
        }
    }

    #[test]
    fn test_teams_channel_new() {
        let config = create_test_config();
        let channel = TeamsChannel::new(config);
        assert_eq!(channel.channel_name(), "teams");
    }

    #[test]
    fn test_format_message() {
        let config = create_test_config();
        let channel = TeamsChannel::new(config);

        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        let message = channel.format_message(&alert);

        assert_eq!(message["@type"], "MessageCard");
        assert!(message["title"].as_str().unwrap().contains("Alert"));
        assert!(message["summary"].as_str().unwrap().contains("example.com"));
    }
}
