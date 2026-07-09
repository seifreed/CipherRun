// Monitoring configuration

use crate::Result;
use crate::error::TlsError;
use crate::security::validate_hostname;
use crate::monitor::types::AlertThresholds;
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const MAX_MONITOR_CONFIG_BYTES: u64 = 1024 * 1024;

/// Main monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub monitor: MonitorSettings,
}

/// Monitor settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorSettings {
    pub default_interval_seconds: u64,
    pub max_concurrent_scans: usize,
    pub database_url: Option<String>,
    pub alerts: AlertsConfig,
    pub thresholds: ThresholdsConfig,
    pub deduplication: DeduplicationConfig,
}

/// Alerts configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertsConfig {
    pub email: Option<EmailConfig>,
    pub slack: Option<SlackConfig>,
    pub teams: Option<TeamsConfig>,
    pub pagerduty: Option<PagerDutyConfig>,
    pub webhook: Option<WebhookConfig>,
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub use_tls: bool,
}

/// Slack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

/// Microsoft Teams configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

/// PagerDuty configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    pub enabled: bool,
    pub integration_key: String,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// Alert thresholds configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdsConfig {
    pub expiry_30d: bool,
    pub expiry_14d: bool,
    pub expiry_7d: bool,
    pub expiry_1d: bool,
    pub on_certificate_change: bool,
}

impl Default for ThresholdsConfig {
    fn default() -> Self {
        Self {
            expiry_30d: true,
            expiry_14d: true,
            expiry_7d: true,
            expiry_1d: true,
            on_certificate_change: true,
        }
    }
}

impl From<&ThresholdsConfig> for AlertThresholds {
    fn from(config: &ThresholdsConfig) -> Self {
        Self {
            expiry_30d: config.expiry_30d,
            expiry_14d: config.expiry_14d,
            expiry_7d: config.expiry_7d,
            expiry_1d: config.expiry_1d,
            on_change: config.on_certificate_change,
        }
    }
}

/// Alert deduplication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    #[serde(default = "default_deduplication_window_hours")]
    pub window_hours: u64,
}

fn default_deduplication_window_hours() -> u64 {
    24
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            window_hours: default_deduplication_window_hours(),
        }
    }
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            default_interval_seconds: 3600,
            max_concurrent_scans: 10,
            database_url: None,
            alerts: AlertsConfig::default(),
            thresholds: ThresholdsConfig::default(),
            deduplication: DeduplicationConfig::default(),
        }
    }
}

impl MonitorConfig {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let size = fs::metadata(path.as_ref())
            .map_err(|e| TlsError::FileSystemError {
                path: path.as_ref().display().to_string(),
                source: e,
            })?
            .len();
        if size > MAX_MONITOR_CONFIG_BYTES {
            return Err(TlsError::InvalidInput {
                message: format!(
                    "Monitor config file too large: {} bytes (max {})",
                    size, MAX_MONITOR_CONFIG_BYTES
                ),
            });
        }
        let contents =
            fs::read_to_string(path.as_ref()).map_err(|e| TlsError::FileSystemError {
                path: path.as_ref().display().to_string(),
                source: e,
            })?;

        let config: MonitorConfig =
            toml::from_str(&contents).map_err(|e| TlsError::ConfigError {
                message: format!("Failed to parse TOML config: {e}"),
            })?;
        config.validate()?;

        Ok(config)
    }

    /// Create default configuration
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            monitor: MonitorSettings::default(),
        }
    }

    /// Save configuration to TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let toml_str = toml::to_string_pretty(self).map_err(|e| TlsError::ConfigError {
            message: format!("Failed to serialize config: {e}"),
        })?;

        fs::write(path.as_ref(), toml_str).map_err(|e| TlsError::FileSystemError {
            path: path.as_ref().display().to_string(),
            source: e,
        })?;

        Ok(())
    }

    /// Get list of enabled alert channels
    pub fn enabled_channels(&self) -> Vec<String> {
        let mut channels = Vec::new();

        if let Some(ref email) = self.monitor.alerts.email
            && email.enabled
        {
            channels.push("email".to_string());
        }

        if let Some(ref slack) = self.monitor.alerts.slack
            && slack.enabled
        {
            channels.push("slack".to_string());
        }

        if let Some(ref teams) = self.monitor.alerts.teams
            && teams.enabled
        {
            channels.push("teams".to_string());
        }

        if let Some(ref pagerduty) = self.monitor.alerts.pagerduty
            && pagerduty.enabled
        {
            channels.push("pagerduty".to_string());
        }

        if let Some(ref webhook) = self.monitor.alerts.webhook
            && webhook.enabled
        {
            channels.push("webhook".to_string());
        }

        channels
    }
}

impl MonitorConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.monitor.default_interval_seconds == 0 {
            return Err(TlsError::ConfigError {
                message: "monitor.default_interval_seconds must be greater than 0".to_string(),
            });
        }
        if self.monitor.max_concurrent_scans == 0 {
            return Err(TlsError::ConfigError {
                message: "monitor.max_concurrent_scans must be greater than 0".to_string(),
            });
        }
        if self.monitor.deduplication.window_hours == 0 {
            return Err(TlsError::ConfigError {
                message: "monitor.deduplication.window_hours must be greater than 0".to_string(),
            });
        }
        self.validate_alerts()?;
        Ok(())
    }

    fn validate_alerts(&self) -> Result<()> {
        if let Some(email) = &self.monitor.alerts.email
            && email.enabled
            && (email.smtp_server.trim().is_empty()
                || email.smtp_port == 0
                || email.from_address.trim().is_empty()
                || email.to_addresses.is_empty()
                || email.to_addresses.iter().any(|addr| addr.trim().is_empty())
                || email.username.trim().is_empty())
        {
            return Err(TlsError::ConfigError {
                message: "enabled email alerts require SMTP server, port, sender, recipients, and username".to_string(),
            });
        }
        if let Some(email) = &self.monitor.alerts.email
            && email.enabled
        {
            validate_hostname(&email.smtp_server).map_err(|error| TlsError::ConfigError {
                message: format!("Invalid email smtp_server: {error}"),
            })?;
        }
        if let Some(slack) = &self.monitor.alerts.slack
            && slack.enabled
        {
            Self::validate_url("Slack webhook_url", &slack.webhook_url)?;
        }
        if let Some(teams) = &self.monitor.alerts.teams
            && teams.enabled
        {
            Self::validate_url("Teams webhook_url", &teams.webhook_url)?;
        }
        if let Some(pagerduty) = &self.monitor.alerts.pagerduty
            && pagerduty.enabled
            && pagerduty.integration_key.trim().is_empty()
        {
            return Err(TlsError::ConfigError {
                message: "enabled PagerDuty alerts require integration_key".to_string(),
            });
        }
        if let Some(webhook) = &self.monitor.alerts.webhook
            && webhook.enabled
        {
            Self::validate_url("webhook url", &webhook.url)?;
            for (name, value) in &webhook.headers {
                HeaderName::from_bytes(name.as_bytes()).map_err(|error| TlsError::ConfigError {
                    message: format!("Invalid webhook header name '{name}': {error}"),
                })?;
                HeaderValue::from_str(value).map_err(|error| TlsError::ConfigError {
                    message: format!("Invalid webhook header value for '{name}': {error}"),
                })?;
            }
        }
        Ok(())
    }

    fn validate_url(label: &str, value: &str) -> Result<()> {
        if value.trim().is_empty() {
            return Err(TlsError::ConfigError {
                message: format!("enabled {label} must not be empty"),
            });
        }
        let url = reqwest::Url::parse(value).map_err(|error| TlsError::ConfigError {
            message: format!("Invalid {label}: {error}"),
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(TlsError::ConfigError {
                message: format!("Invalid {label}: scheme must be http or https"),
            });
        }
        if matches!(url.port(), Some(0)) {
            return Err(TlsError::ConfigError {
                message: format!("Invalid {label}: port must be between 1 and 65535"),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(TlsError::ConfigError {
                message: format!("Invalid {label}: must not contain credentials"),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MonitorConfig::default();
        assert_eq!(config.monitor.default_interval_seconds, 3600);
        assert_eq!(config.monitor.max_concurrent_scans, 10);
        assert!(config.monitor.thresholds.expiry_7d);
    }

    #[test]
    fn test_config_serialization() {
        let config = MonitorConfig::default();
        let toml_str = toml::to_string(&config).expect("test assertion should succeed");
        assert!(toml_str.contains("default_interval_seconds"));
        assert!(toml_str.contains("max_concurrent_scans"));
    }

    #[test]
    fn test_config_deserialization_applies_monitor_defaults() {
        let config: MonitorConfig = toml::from_str(
            r#"
[monitor]
default_interval_seconds = 600
"#,
        )
        .expect("partial monitor config should use defaults");

        assert_eq!(config.monitor.default_interval_seconds, 600);
        assert_eq!(config.monitor.max_concurrent_scans, 10);
        assert!(config.monitor.thresholds.expiry_7d);
        assert_eq!(config.monitor.deduplication.window_hours, 24);
    }

    #[test]
    fn test_config_deserialization_applies_partial_threshold_defaults() {
        let config: MonitorConfig = toml::from_str(
            r#"
[monitor]
default_interval_seconds = 600
max_concurrent_scans = 2

[monitor.thresholds]
expiry_7d = false
"#,
        )
        .expect("partial thresholds config should use defaults");

        assert!(!config.monitor.thresholds.expiry_7d);
        assert!(config.monitor.thresholds.expiry_30d);
        assert!(config.monitor.thresholds.on_certificate_change);
    }

    #[test]
    fn test_enabled_channels_none() {
        let config = MonitorConfig::default();
        let channels = config.enabled_channels();
        assert!(channels.is_empty());
    }

    #[test]
    fn test_enabled_channels_email() {
        let mut config = MonitorConfig::default();
        config.monitor.alerts.email = Some(EmailConfig {
            enabled: true,
            smtp_server: "smtp.example.com".to_string(),
            smtp_port: 587,
            from_address: "alerts@example.com".to_string(),
            to_addresses: vec!["admin@example.com".to_string()],
            username: "user".to_string(),
            password: "pass".to_string(),
            use_tls: true,
        });

        let channels = config.enabled_channels();
        assert_eq!(channels, vec!["email"]);
    }

    #[test]
    fn test_enabled_channels_multiple() {
        let mut config = MonitorConfig::default();
        config.monitor.alerts.email = Some(EmailConfig {
            enabled: true,
            smtp_server: "smtp.example.com".to_string(),
            smtp_port: 587,
            from_address: "alerts@example.com".to_string(),
            to_addresses: vec!["admin@example.com".to_string()],
            username: "user".to_string(),
            password: "pass".to_string(),
            use_tls: true,
        });
        config.monitor.alerts.slack = Some(SlackConfig {
            enabled: true,
            webhook_url: "https://example.com".to_string(),
        });

        let channels = config.enabled_channels();
        assert!(channels.contains(&"email".to_string()));
        assert!(channels.contains(&"slack".to_string()));
    }

    #[test]
    fn test_deduplication_default_window() {
        let dedup = DeduplicationConfig::default();
        assert_eq!(dedup.window_hours, 24);
    }

    #[test]
    fn test_from_file_rejects_zero_interval() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor]
default_interval_seconds = 0
max_concurrent_scans = 1
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("zero interval should fail");

        assert!(err.to_string().contains("default_interval_seconds"));
    }

    #[test]
    fn test_from_file_rejects_zero_concurrency() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor]
default_interval_seconds = 60
max_concurrent_scans = 0
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("zero concurrency should fail");

        assert!(err.to_string().contains("max_concurrent_scans"));
    }

    #[test]
    fn test_from_file_rejects_zero_deduplication_window() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor]
default_interval_seconds = 60
max_concurrent_scans = 1

[monitor.deduplication]
window_hours = 0
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("zero dedup window should fail");

        assert!(err.to_string().contains("window_hours"));
    }

    #[test]
    fn test_from_file_rejects_enabled_slack_without_webhook() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor.alerts.slack]
enabled = true
webhook_url = " "
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("empty Slack webhook should fail");

        assert!(err.to_string().contains("Slack"));
    }

    #[test]
    fn test_from_file_rejects_oversized_config_before_read() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        let file = fs::File::create(&path).expect("config should be created");
        file.set_len(MAX_MONITOR_CONFIG_BYTES + 1)
            .expect("config should be resized");

        let err = MonitorConfig::from_file(&path).expect_err("oversized config should fail");
        assert!(err.to_string().contains("Monitor config file too large"));
    }

    #[test]
    fn test_from_file_rejects_enabled_email_without_recipients() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor.alerts.email]
enabled = true
smtp_server = "smtp.example.com"
smtp_port = 587
from_address = "alerts@example.com"
to_addresses = []
username = "user"
password = "pass"
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("empty email recipients should fail");

        assert!(err.to_string().contains("email alerts"));
    }

    #[test]
    fn test_from_file_rejects_enabled_webhook_without_url() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor.alerts.webhook]
enabled = true
url = ""
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("empty webhook url should fail");

        assert!(err.to_string().contains("webhook url"));
    }

    #[test]
    fn test_from_file_rejects_enabled_webhook_invalid_header() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor.alerts.webhook]
enabled = true
url = "https://webhook.example.com/alerts"

[monitor.alerts.webhook.headers]
"Bad Header" = "value"
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("bad webhook header should fail");

        assert!(err.to_string().contains("Invalid webhook header name"));
    }

    #[test]
    fn test_from_file_rejects_enabled_slack_invalid_url_scheme() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor.alerts.slack]
enabled = true
webhook_url = "file:///tmp/hook"
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("bad Slack URL should fail");

        assert!(err.to_string().contains("scheme must be http or https"));
    }

    #[test]
    fn test_from_file_rejects_enabled_slack_zero_port_url() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor.alerts.slack]
enabled = true
webhook_url = "https://webhook.example.com:0/alerts"
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("zero port Slack URL should fail");

        assert!(err.to_string().contains("port must be between 1 and 65535"));
    }

    #[test]
    fn test_from_file_rejects_enabled_teams_credentials() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("monitor.toml");
        fs::write(
            &path,
            r#"
[monitor.alerts.teams]
enabled = true
webhook_url = "https://user:pass@outlook.office.com/webhook/TEST"
"#,
        )
        .expect("test assertion should succeed");

        let err = MonitorConfig::from_file(&path).expect_err("credentials should fail");

        assert!(err.to_string().contains("must not contain credentials"));
    }
}
