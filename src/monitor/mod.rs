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
