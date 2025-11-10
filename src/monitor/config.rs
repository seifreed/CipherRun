// Monitoring configuration

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Main monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub monitor: MonitorSettings,
}

/// Monitor settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSettings {
    pub default_interval_seconds: u64,
    pub max_concurrent_scans: usize,
    pub database_url: Option<String>,
    pub alerts: AlertsConfig,
    pub thresholds: ThresholdsConfig,
    pub deduplication: DeduplicationConfig,
}

/// Alerts configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
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

/// Alert deduplication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    pub window_hours: u64,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self { window_hours: 24 }
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
        let contents = fs::read_to_string(path.as_ref()).map_err(|e| {
            anyhow::anyhow!("Failed to read config file {:?}: {}", path.as_ref(), e)
        })?;

        let config: MonitorConfig = toml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse TOML config: {}", e))?;

        Ok(config)
    }

    /// Create default configuration
    pub fn default() -> Self {
        Self {
            monitor: MonitorSettings::default(),
        }
    }

    /// Save configuration to TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;

        fs::write(path.as_ref(), toml_str).map_err(|e| {
            anyhow::anyhow!("Failed to write config file {:?}: {}", path.as_ref(), e)
        })?;

        Ok(())
    }

    /// Get list of enabled alert channels
    pub fn enabled_channels(&self) -> Vec<String> {
        let mut channels = Vec::new();

        if let Some(ref email) = self.monitor.alerts.email
            && email.enabled {
                channels.push("email".to_string());
            }

        if let Some(ref slack) = self.monitor.alerts.slack
            && slack.enabled {
                channels.push("slack".to_string());
            }

        if let Some(ref teams) = self.monitor.alerts.teams
            && teams.enabled {
                channels.push("teams".to_string());
            }

        if let Some(ref pagerduty) = self.monitor.alerts.pagerduty
            && pagerduty.enabled {
                channels.push("pagerduty".to_string());
            }

        if let Some(ref webhook) = self.monitor.alerts.webhook
            && webhook.enabled {
                channels.push("webhook".to_string());
            }

        channels
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
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("default_interval_seconds"));
        assert!(toml_str.contains("max_concurrent_scans"));
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
}
