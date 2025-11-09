// PagerDuty Alert Channel - Events API v2

use crate::monitor::alerts::{Alert, AlertChannel, AlertType};
use crate::monitor::config::PagerDutyConfig;
use crate::monitor::detector::ChangeSeverity;
use crate::Result;
use async_trait::async_trait;
use serde_json::json;

const PAGERDUTY_EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// PagerDuty alert channel
pub struct PagerDutyChannel {
    config: PagerDutyConfig,
    client: reqwest::Client,
}

impl PagerDutyChannel {
    /// Create new PagerDuty channel
    pub fn new(config: PagerDutyConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Convert severity to PagerDuty severity
    fn severity_to_pd(&self, severity: &ChangeSeverity) -> &str {
        match severity {
            ChangeSeverity::Critical => "critical",
            ChangeSeverity::High => "error",
            ChangeSeverity::Medium => "warning",
            ChangeSeverity::Low => "info",
            ChangeSeverity::Info => "info",
        }
    }

    /// Format alert as PagerDuty event
    fn format_event(&self, alert: &Alert) -> serde_json::Value {
        let severity = self.severity_to_pd(&alert.severity);

        let mut custom_details = json!({
            "hostname": alert.hostname,
            "severity": alert.severity.to_string(),
            "timestamp": alert.timestamp.to_rfc3339(),
        });

        // Add alert-type specific details
        match &alert.alert_type {
            AlertType::CertificateChange { changes } => {
                let changes_desc = changes
                    .iter()
                    .map(|c| format!("{:?}: {}", c.change_type, c.description))
                    .collect::<Vec<_>>()
                    .join(", ");

                custom_details["change_count"] = json!(changes.len());
                custom_details["changes"] = json!(changes_desc);
            }
            AlertType::ExpiryWarning { days_remaining } => {
                custom_details["days_remaining"] = json!(days_remaining);
            }
            AlertType::ValidationFailure { reason } => {
                custom_details["validation_failure"] = json!(reason);
            }
            AlertType::ScanFailure { error } => {
                custom_details["scan_error"] = json!(error);
            }
        }

        // Add certificate details
        if let Some(ref serial) = alert.details.certificate_serial {
            custom_details["certificate_serial"] = json!(serial);
        }
        if let Some(ref issuer) = alert.details.certificate_issuer {
            custom_details["certificate_issuer"] = json!(issuer);
        }
        if let Some(ref expiry) = alert.details.certificate_expiry {
            custom_details["certificate_expiry"] = json!(expiry);
        }

        json!({
            "routing_key": self.config.integration_key,
            "event_action": "trigger",
            "dedup_key": format!("cipherrun:{}:{}", alert.hostname, alert.timestamp.timestamp()),
            "payload": {
                "summary": alert.message,
                "source": "CipherRun Monitor",
                "severity": severity,
                "timestamp": alert.timestamp.to_rfc3339(),
                "component": "certificate-monitor",
                "group": "tls-security",
                "class": "certificate",
                "custom_details": custom_details
            }
        })
    }
}

#[async_trait]
impl AlertChannel for PagerDutyChannel {
    async fn send_alert(&self, alert: &Alert) -> Result<()> {
        let event = self.format_event(alert);

        let response = self
            .client
            .post(PAGERDUTY_EVENTS_URL)
            .json(&event)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow::anyhow!(
                "PagerDuty API returned status {}: {}",
                status,
                body
            )
            .into());
        }

        Ok(())
    }

    fn channel_name(&self) -> &str {
        "pagerduty"
    }

    async fn test_connection(&self) -> Result<()> {
        let test_event = json!({
            "routing_key": self.config.integration_key,
            "event_action": "trigger",
            "dedup_key": format!("cipherrun:test:{}", chrono::Utc::now().timestamp()),
            "payload": {
                "summary": "Test alert from CipherRun monitoring",
                "source": "CipherRun Monitor",
                "severity": "info",
                "component": "certificate-monitor",
                "custom_details": {
                    "test": true,
                    "message": "This is a test alert to verify PagerDuty integration"
                }
            }
        });

        let response = self
            .client
            .post(PAGERDUTY_EVENTS_URL)
            .json(&test_event)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(
                anyhow::anyhow!("PagerDuty test failed: {}", response.status()).into(),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> PagerDutyConfig {
        PagerDutyConfig {
            enabled: true,
            integration_key: "test_integration_key".to_string(),
        }
    }

    #[test]
    fn test_pagerduty_channel_new() {
        let config = create_test_config();
        let channel = PagerDutyChannel::new(config);
        assert_eq!(channel.channel_name(), "pagerduty");
    }

    #[test]
    fn test_severity_conversion() {
        let config = create_test_config();
        let channel = PagerDutyChannel::new(config);

        assert_eq!(channel.severity_to_pd(&ChangeSeverity::Critical), "critical");
        assert_eq!(channel.severity_to_pd(&ChangeSeverity::High), "error");
        assert_eq!(channel.severity_to_pd(&ChangeSeverity::Medium), "warning");
        assert_eq!(channel.severity_to_pd(&ChangeSeverity::Low), "info");
        assert_eq!(channel.severity_to_pd(&ChangeSeverity::Info), "info");
    }

    #[test]
    fn test_format_event() {
        let config = create_test_config();
        let channel = PagerDutyChannel::new(config);

        let alert = Alert::scan_failure(
            "example.com".to_string(),
            "Connection refused".to_string(),
        );

        let event = channel.format_event(&alert);

        assert_eq!(event["routing_key"], "test_integration_key");
        assert_eq!(event["event_action"], "trigger");
        assert!(event["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("example.com"));
    }
}
