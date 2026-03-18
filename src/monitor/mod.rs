// Certificate Monitoring System
//
// This module provides a complete 24/7 certificate monitoring daemon that:
// - Continuously scans configured domains for certificate changes
// - Detects certificate renewals, issuer changes, and expiry warnings
// - Sends alerts through multiple channels (Email, Slack, Teams, PagerDuty, Webhooks)
// - Stores scan history in a database for tracking
// - Supports graceful shutdown and hot-reload of configurations

pub mod alerts;
pub mod config;
pub mod daemon;
pub mod detector;
pub mod inventory;
pub mod scheduler;
pub mod types;

// Re-export commonly used types
pub use alerts::{Alert, AlertChannel, AlertManager, AlertType};
pub use config::MonitorConfig;
pub use daemon::MonitorDaemon;
pub use detector::{ChangeDetector, ChangeEvent, ChangeSeverity, ChangeType};
pub use inventory::{AlertThresholds, CertificateInventory, MonitoredDomain};
pub use scheduler::SchedulingEngine;
pub use types::{ScanHistory, ScanStatus};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_reexports_basic() {
        let thresholds = AlertThresholds::default();
        assert!(thresholds.on_change);
        assert_eq!(ScanStatus::Success.to_string(), "Success");
    }

    #[test]
    fn test_monitor_reexports_change_event() {
        let event = ChangeEvent {
            change_type: ChangeType::IssuerChange,
            severity: ChangeSeverity::Low,
            description: "Issuer changed".to_string(),
            previous_value: Some("Old".to_string()),
            current_value: Some("New".to_string()),
            detected_at: chrono::Utc::now(),
        };

        assert_eq!(event.severity, ChangeSeverity::Low);
    }
}
