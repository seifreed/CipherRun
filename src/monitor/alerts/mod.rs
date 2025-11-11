// Alert System - Multi-channel alerting

pub mod channels;
pub mod email;
pub mod pagerduty;
pub mod slack;
pub mod teams;
pub mod webhook;

use crate::Result;
use crate::monitor::config::MonitorConfig;
use crate::monitor::detector::{ChangeEvent, ChangeSeverity};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub use channels::AlertChannel;

/// Alert type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertType {
    CertificateChange { changes: Vec<ChangeEvent> },
    ExpiryWarning { days_remaining: i64 },
    ValidationFailure { reason: String },
    ScanFailure { error: String },
}

/// Alert details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDetails {
    pub certificate_serial: Option<String>,
    pub certificate_issuer: Option<String>,
    pub certificate_expiry: Option<String>,
    pub previous_serial: Option<String>,
    pub scan_time: DateTime<Utc>,
}

/// Alert message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub hostname: String,
    pub alert_type: AlertType,
    pub severity: ChangeSeverity,
    pub message: String,
    pub details: AlertDetails,
    pub timestamp: DateTime<Utc>,
}

impl Alert {
    /// Create certificate change alert
    pub fn certificate_change(
        hostname: String,
        changes: Vec<ChangeEvent>,
        details: AlertDetails,
    ) -> Self {
        let severity = changes
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(ChangeSeverity::Info);

        let message = format!(
            "Certificate changed for {} ({} changes detected)",
            hostname,
            changes.len()
        );

        Self {
            hostname,
            alert_type: AlertType::CertificateChange { changes },
            severity,
            message,
            details,
            timestamp: Utc::now(),
        }
    }

    /// Create expiry warning alert
    pub fn expiry_warning(hostname: String, days_remaining: i64, details: AlertDetails) -> Self {
        let severity = if days_remaining <= 1 {
            ChangeSeverity::Critical
        } else if days_remaining <= 7 {
            ChangeSeverity::High
        } else if days_remaining <= 14 {
            ChangeSeverity::Medium
        } else {
            ChangeSeverity::Low
        };

        let message = format!(
            "Certificate for {} expires in {} days",
            hostname, days_remaining
        );

        Self {
            hostname,
            alert_type: AlertType::ExpiryWarning { days_remaining },
            severity,
            message,
            details,
            timestamp: Utc::now(),
        }
    }

    /// Create validation failure alert
    pub fn validation_failure(hostname: String, reason: String, details: AlertDetails) -> Self {
        Self {
            hostname: hostname.clone(),
            alert_type: AlertType::ValidationFailure {
                reason: reason.clone(),
            },
            severity: ChangeSeverity::High,
            message: format!("Certificate validation failed for {}: {}", hostname, reason),
            details,
            timestamp: Utc::now(),
        }
    }

    /// Create scan failure alert
    pub fn scan_failure(hostname: String, error: String) -> Self {
        Self {
            hostname: hostname.clone(),
            alert_type: AlertType::ScanFailure {
                error: error.clone(),
            },
            severity: ChangeSeverity::Medium,
            message: format!("Failed to scan {}: {}", hostname, error),
            details: AlertDetails {
                certificate_serial: None,
                certificate_issuer: None,
                certificate_expiry: None,
                previous_serial: None,
                scan_time: Utc::now(),
            },
            timestamp: Utc::now(),
        }
    }

    /// Get a unique key for deduplication
    pub fn dedup_key(&self) -> String {
        match &self.alert_type {
            AlertType::CertificateChange { .. } => {
                format!("change:{}", self.hostname)
            }
            AlertType::ExpiryWarning { days_remaining } => {
                format!("expiry:{}:{}", self.hostname, days_remaining)
            }
            AlertType::ValidationFailure { reason } => {
                format!("validation:{}:{}", self.hostname, reason)
            }
            AlertType::ScanFailure { .. } => {
                format!("scan:{}", self.hostname)
            }
        }
    }
}

/// Alert manager - coordinates multiple alert channels
pub struct AlertManager {
    channels: Vec<Box<dyn AlertChannel>>,
    recent_alerts: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    dedup_window: Duration,
}

impl AlertManager {
    /// Create new alert manager
    pub fn new(dedup_window_hours: u64) -> Self {
        Self {
            channels: Vec::new(),
            recent_alerts: Arc::new(Mutex::new(HashMap::new())),
            dedup_window: Duration::hours(dedup_window_hours as i64),
        }
    }

    /// Create from configuration
    pub async fn from_config(config: &MonitorConfig) -> Result<Self> {
        let mut manager = Self::new(config.monitor.deduplication.window_hours);

        // Initialize email channel if configured
        if let Some(ref email_config) = config.monitor.alerts.email
            && email_config.enabled
        {
            let channel = email::EmailChannel::new(email_config.clone())?;
            manager.add_channel(Box::new(channel));
        }

        // Initialize Slack channel if configured
        if let Some(ref slack_config) = config.monitor.alerts.slack
            && slack_config.enabled
        {
            let channel = slack::SlackChannel::new(slack_config.clone());
            manager.add_channel(Box::new(channel));
        }

        // Initialize Teams channel if configured
        if let Some(ref teams_config) = config.monitor.alerts.teams
            && teams_config.enabled
        {
            let channel = teams::TeamsChannel::new(teams_config.clone());
            manager.add_channel(Box::new(channel));
        }

        // Initialize PagerDuty channel if configured
        if let Some(ref pd_config) = config.monitor.alerts.pagerduty
            && pd_config.enabled
        {
            let channel = pagerduty::PagerDutyChannel::new(pd_config.clone());
            manager.add_channel(Box::new(channel));
        }

        // Initialize Webhook channel if configured
        if let Some(ref webhook_config) = config.monitor.alerts.webhook
            && webhook_config.enabled
        {
            let channel = webhook::WebhookChannel::new(webhook_config.clone());
            manager.add_channel(Box::new(channel));
        }

        Ok(manager)
    }

    /// Add an alert channel
    pub fn add_channel(&mut self, channel: Box<dyn AlertChannel>) {
        self.channels.push(channel);
    }

    /// Send alert through all channels
    pub async fn send_alert(&self, alert: &Alert) -> Result<()> {
        // Check for duplicate
        if self.is_duplicate(alert).await {
            tracing::debug!("Alert deduplicated: {}", alert.dedup_key());
            return Ok(());
        }

        // Record alert
        self.record_alert(alert).await;

        // Send to all channels concurrently
        let mut tasks = Vec::new();

        for channel in &self.channels {
            let alert_clone = alert.clone();
            let channel_name = channel.channel_name().to_string();

            let task = async move {
                match channel.send_alert(&alert_clone).await {
                    Ok(_) => {
                        tracing::info!("Alert sent via {}: {}", channel_name, alert_clone.message);
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!("Failed to send alert via {}: {}", channel_name, e);
                        Err(e)
                    }
                }
            };

            tasks.push(task);
        }

        // Wait for all channels (but don't fail if some fail)
        let results = futures::future::join_all(tasks).await;

        // Check if at least one succeeded
        let success_count = results.iter().filter(|r| r.is_ok()).count();

        if success_count == 0 && !self.channels.is_empty() {
            return Err(anyhow::anyhow!("All alert channels failed").into());
        }

        Ok(())
    }

    /// Check if alert is a duplicate
    async fn is_duplicate(&self, alert: &Alert) -> bool {
        let recent = self.recent_alerts.lock().await;
        let key = alert.dedup_key();

        if let Some(last_sent) = recent.get(&key) {
            let elapsed = Utc::now() - *last_sent;
            elapsed < self.dedup_window
        } else {
            false
        }
    }

    /// Record alert for deduplication
    async fn record_alert(&self, alert: &Alert) {
        let mut recent = self.recent_alerts.lock().await;
        recent.insert(alert.dedup_key(), alert.timestamp);

        // Clean old entries
        let cutoff = Utc::now() - self.dedup_window;
        recent.retain(|_, &mut time| time > cutoff);
    }

    /// Get channel count
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Test all channels
    pub async fn test_channels(&self) -> Vec<(String, Result<()>)> {
        let mut results = Vec::new();

        for channel in &self.channels {
            let test_alert = Alert {
                hostname: "test.example.com".to_string(),
                alert_type: AlertType::ScanFailure {
                    error: "This is a test alert".to_string(),
                },
                severity: ChangeSeverity::Info,
                message: "Test alert from CipherRun monitoring".to_string(),
                details: AlertDetails {
                    certificate_serial: None,
                    certificate_issuer: None,
                    certificate_expiry: None,
                    previous_serial: None,
                    scan_time: Utc::now(),
                },
                timestamp: Utc::now(),
            };

            let result = channel.send_alert(&test_alert).await;
            results.push((channel.channel_name().to_string(), result));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_dedup_key() {
        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        assert_eq!(alert.dedup_key(), "scan:example.com");
    }

    #[test]
    fn test_expiry_warning_severity() {
        let details = AlertDetails {
            certificate_serial: None,
            certificate_issuer: None,
            certificate_expiry: None,
            previous_serial: None,
            scan_time: Utc::now(),
        };

        let alert1 = Alert::expiry_warning("example.com".to_string(), 1, details.clone());
        assert_eq!(alert1.severity, ChangeSeverity::Critical);

        let alert7 = Alert::expiry_warning("example.com".to_string(), 7, details.clone());
        assert_eq!(alert7.severity, ChangeSeverity::High);

        let alert14 = Alert::expiry_warning("example.com".to_string(), 14, details.clone());
        assert_eq!(alert14.severity, ChangeSeverity::Medium);

        let alert30 = Alert::expiry_warning("example.com".to_string(), 30, details);
        assert_eq!(alert30.severity, ChangeSeverity::Low);
    }

    #[tokio::test]
    async fn test_alert_manager_deduplication() {
        let manager = AlertManager::new(24);

        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        // First alert should not be duplicate
        assert!(!manager.is_duplicate(&alert).await);

        // Record it
        manager.record_alert(&alert).await;

        // Same alert should now be duplicate
        assert!(manager.is_duplicate(&alert).await);
    }

    #[test]
    fn test_alert_manager_new() {
        let manager = AlertManager::new(24);
        assert_eq!(manager.channel_count(), 0);
    }
}
