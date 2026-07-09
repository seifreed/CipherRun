// Microsoft Teams Alert Channel - Webhook integration

use super::{raw_webhook_host, validated_webhook_target};
use crate::Result;
use crate::error::TlsError;
use crate::monitor::alerts::{Alert, AlertChannel, AlertType};
use crate::monitor::config::TeamsConfig;
use crate::monitor::detector::ChangeSeverity;
use crate::security::validate_hostname;
use crate::security::input_validation::looks_like_obfuscated_ip;
use async_trait::async_trait;
use serde_json::json;

/// Microsoft Teams alert channel
pub struct TeamsChannel {
    config: TeamsConfig,
}

impl TeamsChannel {
    /// Create new Teams channel
    pub fn new(config: TeamsConfig) -> Result<Self> {
        if raw_webhook_host(&config.webhook_url).is_some_and(looks_like_obfuscated_ip) {
            return Err(TlsError::ConfigError {
                message: "Invalid Teams webhook_url: obfuscated IP notation is not allowed"
                    .to_string(),
            });
        }
        let url =
            reqwest::Url::parse(&config.webhook_url).map_err(|error| TlsError::ConfigError {
                message: format!("Invalid Teams webhook_url: {error}"),
            })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(TlsError::ConfigError {
                message: "Invalid Teams webhook_url: scheme must be http or https".to_string(),
            });
        }
        if matches!(url.port(), Some(0)) {
            return Err(TlsError::ConfigError {
                message: "Invalid Teams webhook_url: port must be between 1 and 65535".to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(TlsError::ConfigError {
                message: "Teams webhook_url must not contain credentials".to_string(),
            });
        }
        validate_hostname(url.host_str().unwrap_or("")).map_err(|error| TlsError::ConfigError {
            message: format!("Invalid Teams webhook_url: {error}"),
        })?;
        Ok(Self { config })
    }

    /// Format alert as Teams Adaptive Card message
    fn format_message(&self, alert: &Alert) -> serde_json::Value {
        let theme_color = match alert.severity {
            ChangeSeverity::Critical => "CC0000",
            ChangeSeverity::High => "FF8C00",
            ChangeSeverity::Medium => "FFD700",
            ChangeSeverity::Low => "28A745",
            ChangeSeverity::Info => "17A2B8",
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
        let validated = validated_webhook_target(
            &self.config.webhook_url,
            std::time::Duration::from_secs(10),
        )
        .await?;
        let response = validated
            .client
            .post(validated.url)
            .json(&message)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = super::alert_error_body(response, "Teams error response").await?;
            return Err(TlsError::HttpError {
                status: status.as_u16(),
                details: format!("Teams webhook error: {body}"),
            });
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
        let validated = validated_webhook_target(
            &self.config.webhook_url,
            std::time::Duration::from_secs(10),
        )
        .await?;
        let response = validated
            .client
            .post(validated.url)
            .json(&test_message)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(TlsError::HttpError {
                status: response.status().as_u16(),
                details: "Teams webhook test failed".to_string(),
            });
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
        let channel = TeamsChannel::new(config).expect("test channel construction should succeed");
        assert_eq!(channel.channel_name(), "teams");
    }

    #[test]
    fn test_teams_channel_rejects_invalid_webhook_url() {
        let mut config = create_test_config();
        config.webhook_url = "file:///tmp/hook".to_string();

        assert!(TeamsChannel::new(config).is_err());
    }

    #[test]
    fn test_teams_channel_rejects_credentials() {
        let mut config = create_test_config();
        config.webhook_url = "https://user:pass@outlook.office.com/webhook/TEST".to_string();

        let err = match TeamsChannel::new(config) {
            Ok(_) => panic!("credentials should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("credentials"));
    }

    #[test]
    fn test_teams_channel_rejects_obfuscated_ip_webhook_url() {
        let mut config = create_test_config();
        config.webhook_url = "https://127.1/webhook/TEST".to_string();

        let err = match TeamsChannel::new(config) {
            Ok(_) => panic!("obfuscated IP should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("obfuscated IP notation"));
    }

    #[test]
    fn test_teams_channel_rejects_dotted_ip_webhook_url() {
        let mut config = create_test_config();
        config.webhook_url = "https://10.0.0.1./webhook/TEST".to_string();

        assert!(TeamsChannel::new(config).is_err());
    }

    #[test]
    fn test_format_message() {
        let config = create_test_config();
        let channel = TeamsChannel::new(config).expect("test channel construction should succeed");

        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        let message = channel.format_message(&alert);

        assert_eq!(message["@type"], "MessageCard");
        assert!(message["title"].as_str().unwrap().contains("Alert"));
        assert!(message["summary"].as_str().unwrap().contains("example.com"));
    }
}
