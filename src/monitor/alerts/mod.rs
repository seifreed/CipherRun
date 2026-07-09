// Alert System - Multi-channel alerting

pub mod channels;
pub mod email;
pub mod formatting;
pub mod pagerduty;
pub mod slack;
pub mod teams;
pub mod webhook;

use crate::Result;
use crate::monitor::config::MonitorConfig;
use crate::monitor::detector::{ChangeEvent, ChangeSeverity};
use crate::security::validate_hostname;
use crate::security::input_validation::looks_like_obfuscated_ip;
use crate::security::is_private_ip;
use chrono::{DateTime, Duration, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::lookup_host;

pub use channels::AlertChannel;

const ALERT_ERROR_BODY_LIMIT: u64 = 64 * 1024;

pub(crate) struct ValidatedWebhookTarget {
    pub(crate) url: Url,
    pub(crate) client: reqwest::Client,
}

pub(crate) async fn validated_webhook_target(
    webhook_url: &str,
    timeout: std::time::Duration,
) -> Result<ValidatedWebhookTarget> {
    if raw_webhook_host(webhook_url).is_some_and(looks_like_obfuscated_ip) {
        return Err(crate::error::TlsError::ConfigError {
            message: "Webhook URL must not use obfuscated IP notation".to_string(),
        });
    }

    let url = Url::parse(webhook_url).map_err(|error| crate::error::TlsError::ConfigError {
        message: format!("Invalid webhook url: {error}"),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(crate::error::TlsError::ConfigError {
            message: "Invalid webhook url: scheme must be http or https".to_string(),
        });
    }
    if matches!(url.port(), Some(0)) {
        return Err(crate::error::TlsError::ConfigError {
            message: "Invalid webhook url: port must be between 1 and 65535".to_string(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(crate::error::TlsError::ConfigError {
            message: "Webhook URL must not contain credentials".to_string(),
        });
    }

    let host = url.host_str().ok_or_else(|| crate::error::TlsError::ConfigError {
        message: "Invalid webhook url: host required".to_string(),
    })?;
    validate_hostname(host).map_err(|error| crate::error::TlsError::ConfigError {
        message: format!("Invalid webhook url: {error}"),
    })?;
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host != "localhost"
        && (normalized_host.ends_with(".local") || normalized_host.ends_with(".internal"))
    {
        return Err(crate::error::TlsError::ConfigError {
            message: "Webhook URL must not use private/local hosts".to_string(),
        });
    }
    if looks_like_obfuscated_ip(host) {
        return Err(crate::error::TlsError::ConfigError {
            message: "Webhook URL must not use obfuscated IP notation".to_string(),
        });
    }
    let host_ip = host.parse::<IpAddr>().ok();
    if let Some(ip) = host_ip.filter(|ip| !ip.is_loopback() && is_private_ip(ip)) {
        return Err(crate::error::TlsError::ConfigError {
            message: format!("Webhook URL uses private/internal IP literal {ip}"),
        });
    }
    let port = url.port_or_known_default().unwrap_or(80);
    let addrs: Vec<_> = lookup_host((host, port))
        .await
        .map_err(|error| crate::error::TlsError::Other(format!(
            "Webhook DNS resolution failed for {host}: {error}"
        )))?
        .collect();
    if addrs.is_empty() {
        return Err(crate::error::TlsError::ConfigError {
            message: format!("Webhook DNS resolution returned no addresses for {host}"),
        });
    }
    let mut addrs = addrs;
    addrs.sort_by_key(|addr| addr.ip().is_ipv6());
    validate_webhook_addrs(
        &normalized_host,
        host_ip.is_some_and(|ip| ip.is_loopback()),
        &addrs,
    )?;

    let mut client_builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    for addr in addrs {
        client_builder = client_builder.resolve(host, addr);
    }

    Ok(ValidatedWebhookTarget {
        url,
        client: client_builder.build()?,
    })
}

pub(crate) fn raw_webhook_host(webhook_url: &str) -> Option<&str> {
    let authority = webhook_url.split_once("://")?.1;
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let host = authority.rsplit_once('@').map(|(_, host)| host).unwrap_or(authority);

    if let Some(host) = host.strip_prefix('[') {
        host.split_once(']').map(|(host, _)| host)
    } else {
        Some(host.split_once(':').map_or(host, |(hostname, _)| hostname))
    }
}

fn validate_webhook_addrs(
    normalized_host: &str,
    allow_loopback_only: bool,
    addrs: &[SocketAddr],
) -> Result<()> {
    if normalized_host == "localhost" || allow_loopback_only {
        if addrs.iter().any(|addr| !addr.ip().is_loopback()) {
            return Err(crate::error::TlsError::ConfigError {
                message: "Webhook URL must resolve only to loopback addresses"
                    .to_string(),
            });
        }
        return Ok(());
    }

    if addrs.iter().any(|addr| is_private_ip(&addr.ip())) {
        return Err(crate::error::TlsError::ConfigError {
            message: "Webhook URL resolves to private/internal IP".to_string(),
        });
    }

    Ok(())
}

async fn alert_error_body(response: reqwest::Response, context: &str) -> Result<String> {
    let body =
        crate::utils::http::read_response_body_capped(response, ALERT_ERROR_BODY_LIMIT, context)
            .await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Alert type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertType {
    CertificateChange { changes: Vec<ChangeEvent> },
    ExpiryWarning { days_remaining: i64 },
    ValidationFailure { reason: String },
    ScanFailure { error: String },
}

impl AlertType {
    /// Stable deduplication key for alert grouping (no timestamps).
    /// Same incident type for the same host produces the same key,
    /// enabling proper deduplication in PagerDuty and similar systems.
    pub fn dedup_key(&self) -> String {
        match self {
            AlertType::CertificateChange { changes } => {
                // Group by max severity so an escalation (e.g. a Critical issuer
                // change) is not deduplicated against an earlier low-severity
                // change (e.g. a routine renewal) within the dedup window.
                let severity = changes
                    .iter()
                    .map(|c| c.severity)
                    .max()
                    .unwrap_or(ChangeSeverity::Info);
                format!("cert-change-{}", severity)
            }
            AlertType::ExpiryWarning { days_remaining } => {
                // Group by urgency bracket so "7 days" and "6 days" dedup together
                let bracket = if *days_remaining <= 1 {
                    "critical"
                } else if *days_remaining <= 7 {
                    "week"
                } else {
                    "warning"
                };
                format!("expiry-{}", bracket)
            }
            AlertType::ValidationFailure { .. } => "validation-failure".to_string(),
            AlertType::ScanFailure { .. } => "scan-failure".to_string(),
        }
    }
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

        let message = if days_remaining < 0 {
            format!(
                "Certificate for {} expired {} days ago",
                hostname, -days_remaining
            )
        } else if days_remaining == 0 {
            format!("Certificate for {} expires today", hostname)
        } else {
            format!(
                "Certificate for {} expires in {} days",
                hostname, days_remaining
            )
        };

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
        let message = format!("Certificate validation failed for {}: {}", hostname, reason);
        Self {
            hostname,
            alert_type: AlertType::ValidationFailure { reason },
            severity: ChangeSeverity::High,
            message,
            details,
            timestamp: Utc::now(),
        }
    }

    /// Create scan failure alert
    pub fn scan_failure(hostname: String, error: String) -> Self {
        let message = format!("Failed to scan {}: {}", hostname, error);
        Self {
            hostname,
            alert_type: AlertType::ScanFailure { error },
            severity: ChangeSeverity::Medium,
            message,
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

    /// Get a unique key for deduplication.
    /// Uses the same bracketed approach as AlertType::dedup_key() so that
    /// daily expiry countdown changes (7→6→5 days) don't defeat dedup.
    pub fn dedup_key(&self) -> String {
        format!("{}:{}", self.hostname, self.alert_type.dedup_key())
    }
}

#[cfg(test)]
mod tests_extra {
    use super::*;
    use crate::monitor::detector::{ChangeEvent, ChangeSeverity, ChangeType};

    #[test]
    fn test_certificate_change_alert_severity_and_message() {
        let changes = vec![
            ChangeEvent {
                change_type: ChangeType::Renewal,
                severity: ChangeSeverity::Info,
                description: "Renewed".to_string(),
                previous_value: Some("old".to_string()),
                current_value: Some("new".to_string()),
                detected_at: Utc::now(),
            },
            ChangeEvent {
                change_type: ChangeType::IssuerChange,
                severity: ChangeSeverity::Critical,
                description: "Issuer changed".to_string(),
                previous_value: Some("CA1".to_string()),
                current_value: Some("CA2".to_string()),
                detected_at: Utc::now(),
            },
        ];

        let details = AlertDetails {
            certificate_serial: Some("01".to_string()),
            certificate_issuer: Some("CA2".to_string()),
            certificate_expiry: Some("2030-01-01".to_string()),
            previous_serial: Some("00".to_string()),
            scan_time: Utc::now(),
        };

        let alert = Alert::certificate_change("example.com".to_string(), changes, details);

        assert_eq!(alert.hostname, "example.com");
        assert_eq!(alert.severity, ChangeSeverity::Critical);
        assert!(alert.message.contains("Certificate changed"));
        matches!(alert.alert_type, AlertType::CertificateChange { .. });
    }

    #[test]
    fn test_expiry_warning_severity_and_dedup_key() {
        let details = AlertDetails {
            certificate_serial: Some("01".to_string()),
            certificate_issuer: Some("CA1".to_string()),
            certificate_expiry: Some("2030-01-01".to_string()),
            previous_serial: None,
            scan_time: chrono::Utc::now(),
        };

        let alert = Alert::expiry_warning("example.com".to_string(), 3, details);

        assert_eq!(alert.severity, ChangeSeverity::High);
        assert_eq!(alert.dedup_key(), "example.com:expiry-week");
        matches!(alert.alert_type, AlertType::ExpiryWarning { .. });
    }

    #[tokio::test]
    async fn test_validated_webhook_target_rejects_private_ip_literal() {
        let err = match validated_webhook_target(
            "https://10.0.0.1/alerts",
            std::time::Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => panic!("private IP literal should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("private/internal IP literal"));
    }

    #[tokio::test]
    async fn test_validated_webhook_target_rejects_dotted_ip_literal() {
        let err = match validated_webhook_target(
            "https://10.0.0.1./alerts",
            std::time::Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => panic!("dotted IP literal should fail"),
            Err(err) => err,
        };

        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_validated_webhook_target_rejects_obfuscated_ip_notation() {
        let err = match validated_webhook_target(
            "https://127.1/alerts",
            std::time::Duration::from_secs(1),
        )
        .await
        {
            Ok(_) => panic!("obfuscated IP should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("obfuscated IP notation"));
    }

    #[tokio::test]
    async fn test_validated_webhook_target_allows_localhost() {
        let target = validated_webhook_target(
            "https://localhost/alerts",
            std::time::Duration::from_secs(1),
        )
        .await;

        assert!(target.is_ok());
    }

    #[test]
    fn test_validate_webhook_addrs_rejects_localhost_offloopback() {
        let addrs = [SocketAddr::from(([8, 8, 8, 8], 443))];

        let err = match validate_webhook_addrs("localhost", false, &addrs) {
            Ok(_) => panic!("localhost must not resolve to public IPs"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("resolve only to loopback addresses"));
    }

    #[test]
    fn test_validate_webhook_addrs_rejects_private_resolution() {
        let addrs = [SocketAddr::from(([10, 0, 0, 1], 443))];

        let err = match validate_webhook_addrs("example.com", false, &addrs) {
            Ok(_) => panic!("private resolution should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("private/internal IP"));
    }

    #[test]
    fn test_validate_webhook_addrs_rejects_loopback_resolution_for_public_host() {
        let addrs = [SocketAddr::from(([127, 0, 0, 1], 443))];

        let err = match validate_webhook_addrs("example.com", false, &addrs) {
            Ok(_) => panic!("loopback resolution should fail for public hosts"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("private/internal IP"));
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
    pub fn new(dedup_window_hours: u64) -> Result<Self> {
        if dedup_window_hours == 0 {
            return Err(crate::TlsError::InvalidInput {
                message: "dedup_window_hours must be greater than 0".to_string(),
            });
        }
        let hours =
            i64::try_from(dedup_window_hours).map_err(|error| crate::TlsError::InvalidInput {
                message: format!("dedup_window_hours is too large: {error}"),
            })?;
        let dedup_window =
            Duration::try_hours(hours).ok_or_else(|| crate::TlsError::InvalidInput {
                message: "dedup_window_hours is too large".to_string(),
            })?;

        Ok(Self {
            channels: Vec::new(),
            recent_alerts: Arc::new(Mutex::new(HashMap::new())),
            dedup_window,
        })
    }

    /// Create from configuration
    pub async fn from_config(config: &MonitorConfig) -> Result<Self> {
        let mut manager = Self::new(config.monitor.deduplication.window_hours)?;

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
            let channel = slack::SlackChannel::new(slack_config.clone())?;
            manager.add_channel(Box::new(channel));
        }

        // Initialize Teams channel if configured
        if let Some(ref teams_config) = config.monitor.alerts.teams
            && teams_config.enabled
        {
            let channel = teams::TeamsChannel::new(teams_config.clone())?;
            manager.add_channel(Box::new(channel));
        }

        // Initialize PagerDuty channel if configured
        if let Some(ref pd_config) = config.monitor.alerts.pagerduty
            && pd_config.enabled
        {
            let channel = pagerduty::PagerDutyChannel::new(pd_config.clone())?;
            manager.add_channel(Box::new(channel));
        }

        // Initialize Webhook channel if configured
        if let Some(ref webhook_config) = config.monitor.alerts.webhook
            && webhook_config.enabled
        {
            let channel = webhook::WebhookChannel::new(webhook_config.clone())?;
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
        // Skip if an identical alert was already delivered within the dedup window.
        if self.is_duplicate(alert).await {
            tracing::debug!("Alert deduplicated: {}", alert.dedup_key());
            return Ok(());
        }

        if self.channels.is_empty() {
            tracing::warn!(
                "No alert channels configured — alert not delivered: {}",
                alert.message
            );
            return Ok(());
        }

        // Send to all channels
        let mut success_count = 0;

        for channel in &self.channels {
            let channel_name = channel.channel_name();
            match channel.send_alert(alert).await {
                Ok(_) => {
                    tracing::info!("Alert sent via {}: {}", channel_name, alert.message);
                    success_count += 1;
                }
                Err(e) => {
                    tracing::error!("Failed to send alert via {}: {}", channel_name, e);
                }
            }
        }

        if success_count == 0 {
            // Do NOT record this alert for deduplication: a failed delivery must
            // not suppress the next attempt, or a transient channel outage would
            // silently swallow a genuine alert for the entire dedup window.
            crate::tls_bail!("All alert channels failed");
        }

        // Record dispatch only after at least one channel succeeded.
        self.record_dispatch(alert).await;

        Ok(())
    }

    /// Check whether an identical alert was delivered within the dedup window.
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

    /// Record a successful dispatch for deduplication and prune stale entries.
    async fn record_dispatch(&self, alert: &Alert) {
        let mut recent = self.recent_alerts.lock().await;
        let now = Utc::now();

        // Record actual dispatch time for accurate deduplication.
        recent.insert(alert.dedup_key(), now);

        // Clean old entries
        let cutoff = now - self.dedup_window;
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

        assert_eq!(alert.dedup_key(), "example.com:scan-failure");
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
        let manager = AlertManager::new(24).expect("valid dedup window");

        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        // First alert should not be duplicate
        assert!(!manager.is_duplicate(&alert).await);

        // Record it
        manager.record_dispatch(&alert).await;

        // Same alert should now be duplicate
        assert!(manager.is_duplicate(&alert).await);
    }

    #[test]
    fn test_alert_manager_new() {
        let manager = AlertManager::new(24).expect("valid dedup window");
        assert_eq!(manager.channel_count(), 0);
    }

    #[test]
    fn test_alert_manager_rejects_invalid_dedup_windows() {
        assert!(AlertManager::new(0).is_err());
        assert!(AlertManager::new(u64::MAX).is_err());
    }
}
