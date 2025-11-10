// Monitoring Daemon - Main orchestration

use crate::certificates::parser::{CertificateInfo, CertificateParser};
use crate::monitor::alerts::{Alert, AlertDetails, AlertManager};
use crate::monitor::config::MonitorConfig;
use crate::monitor::detector::ChangeDetector;
use crate::monitor::inventory::{CertificateInventory, MonitoredDomain};
use crate::monitor::scheduler::SchedulingEngine;
use crate::utils::network::Target;
use crate::Result;
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::interval;

/// Main monitoring daemon
pub struct MonitorDaemon {
    config: MonitorConfig,
    inventory: Arc<Mutex<CertificateInventory>>,
    scheduler: Arc<Mutex<SchedulingEngine>>,
    alert_manager: Arc<AlertManager>,
    detector: Arc<ChangeDetector>,
    running: Arc<AtomicBool>,
    scan_semaphore: Arc<Semaphore>,
}

impl MonitorDaemon {
    /// Create new monitoring daemon
    pub async fn new(config: MonitorConfig) -> Result<Self> {
        let max_concurrent = config.monitor.max_concurrent_scans;
        let alert_manager = Arc::new(AlertManager::from_config(&config).await?);

        Ok(Self {
            config,
            inventory: Arc::new(Mutex::new(CertificateInventory::new())),
            scheduler: Arc::new(Mutex::new(SchedulingEngine::new())),
            alert_manager,
            detector: Arc::new(ChangeDetector::new()),
            running: Arc::new(AtomicBool::new(false)),
            scan_semaphore: Arc::new(Semaphore::new(max_concurrent)),
        })
    }

    /// Load domains from file
    pub async fn load_domains(&self, path: &str) -> Result<()> {
        let mut inventory = self.inventory.lock().await;
        inventory.load_from_file(path)?;
        tracing::info!("Loaded {} domains from {}", inventory.len(), path);
        Ok(())
    }

    /// Add a single domain
    pub async fn add_domain(&self, domain: MonitoredDomain) -> Result<()> {
        let mut inventory = self.inventory.lock().await;
        inventory.add_domain(domain)?;
        Ok(())
    }

    /// Start the monitoring daemon
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting CipherRun monitoring daemon");

        self.running.store(true, Ordering::SeqCst);

        // Setup signal handlers
        self.setup_signal_handlers()?;

        // Log configuration
        let inventory = self.inventory.lock().await;
        let enabled_count = inventory.enabled_domains().len();
        drop(inventory);

        tracing::info!(
            "Monitoring {} enabled domains",
            enabled_count
        );
        tracing::info!(
            "Alert channels: {}",
            self.config.enabled_channels().join(", ")
        );
        tracing::info!(
            "Max concurrent scans: {}",
            self.config.monitor.max_concurrent_scans
        );

        // Main monitoring loop
        let mut tick_interval = interval(StdDuration::from_secs(10)); // Check every 10 seconds

        while self.running.load(Ordering::SeqCst) {
            tick_interval.tick().await;

            if let Err(e) = self.run_scan_cycle().await {
                tracing::error!("Error in scan cycle: {}", e);
            }
        }

        tracing::info!("Monitoring daemon stopped");
        Ok(())
    }

    /// Stop the daemon
    pub fn stop(&self) {
        tracing::info!("Stopping monitoring daemon...");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Run a single scan cycle
    async fn run_scan_cycle(&self) -> Result<()> {
        let inventory = self.inventory.lock().await;
        let enabled_domains = inventory.enabled_domains();

        if enabled_domains.is_empty() {
            return Ok(());
        }

        // Clone domains that need scanning
        let domains_to_check: Vec<MonitoredDomain> = enabled_domains.iter().map(|d| (*d).clone()).collect();
        drop(inventory);

        // Get domains due for scanning
        let mut scheduler = self.scheduler.lock().await;
        let due_domains = scheduler.get_domains_to_scan(&domains_to_check);
        let due_count = due_domains.len();
        drop(scheduler);

        if due_count == 0 {
            return Ok(());
        }

        tracing::info!("Scanning {} domains", due_count);

        // Scan domains concurrently (limited by semaphore)
        let mut tasks = Vec::new();

        for domain in due_domains {
            let domain_clone = domain.clone();
            let inventory_clone = Arc::clone(&self.inventory);
            let alert_manager_clone = Arc::clone(&self.alert_manager);
            let detector_clone = Arc::clone(&self.detector);
            let semaphore_clone = Arc::clone(&self.scan_semaphore);

            let task = tokio::spawn(async move {
                // Acquire semaphore permit
                let _permit = semaphore_clone.acquire().await.ok();

                Self::scan_domain_static(
                    &domain_clone,
                    inventory_clone,
                    alert_manager_clone,
                    detector_clone,
                )
                .await
            });

            tasks.push(task);
        }

        // Wait for all scans to complete
        for task in tasks {
            if let Err(e) = task.await {
                tracing::error!("Scan task failed: {}", e);
            }
        }

        Ok(())
    }

    /// Scan a single domain (static method for async task)
    async fn scan_domain_static(
        domain: &MonitoredDomain,
        inventory: Arc<Mutex<CertificateInventory>>,
        alert_manager: Arc<AlertManager>,
        detector: Arc<ChangeDetector>,
    ) -> Result<()> {
        let identifier = domain.identifier();

        tracing::debug!("Scanning {}", identifier);

        // Parse target
        let target = match Target::parse(&identifier).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse target {}: {}", identifier, e);

                let alert = Alert::scan_failure(
                    identifier.clone(),
                    format!("Failed to parse target: {}", e),
                );

                if let Err(e) = alert_manager.send_alert(&alert).await {
                    tracing::error!("Failed to send alert: {}", e);
                }

                return Ok(());
            }
        };

        // Get certificate
        let parser = CertificateParser::new(target);

        let current_cert = match parser.get_leaf_certificate().await {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!("Failed to get certificate for {}: {}", identifier, e);

                // Send scan failure alert
                if domain.alert_thresholds.on_change {
                    let alert = Alert::scan_failure(
                        identifier.clone(),
                        format!("Failed to retrieve certificate: {}", e),
                    );

                    if let Err(e) = alert_manager.send_alert(&alert).await {
                        tracing::error!("Failed to send alert: {}", e);
                    }
                }

                return Ok(());
            }
        };

        // Get previous certificate from inventory
        let mut inventory_guard = inventory.lock().await;
        let previous_cert = inventory_guard
            .get_domain(&identifier)
            .and_then(|d| d.last_certificate.clone());

        // Detect changes
        if let Some(prev) = previous_cert {
            let changes = detector.detect_changes(&prev, &current_cert);

            if !changes.is_empty() {
                tracing::info!(
                    "Detected {} changes for {}",
                    changes.len(),
                    identifier
                );

                // Send change alert if configured
                if domain.alert_thresholds.on_change {
                    let details = AlertDetails {
                        certificate_serial: Some(current_cert.serial_number.clone()),
                        certificate_issuer: Some(current_cert.issuer.clone()),
                        certificate_expiry: Some(current_cert.not_after.clone()),
                        previous_serial: Some(prev.serial_number.clone()),
                        scan_time: Utc::now(),
                    };

                    let alert = Alert::certificate_change(
                        identifier.clone(),
                        changes,
                        details,
                    );

                    if let Err(e) = alert_manager.send_alert(&alert).await {
                        tracing::error!("Failed to send change alert: {}", e);
                    }
                }
            }
        }

        // Check expiry warnings
        Self::check_expiry_warnings(
            &identifier,
            &current_cert,
            &domain.alert_thresholds,
            &alert_manager,
        )
        .await?;

        // Update inventory
        if let Some(domain_mut) = inventory_guard.get_domain_mut(&identifier) {
            domain_mut.update_scan(Some(current_cert));
        }

        tracing::debug!("Completed scan of {}", identifier);

        Ok(())
    }

    /// Check for expiry warnings
    async fn check_expiry_warnings(
        identifier: &str,
        cert: &CertificateInfo,
        thresholds: &crate::monitor::types::AlertThresholds,
        alert_manager: &AlertManager,
    ) -> Result<()> {
        // Parse expiry date
        let expiry = match chrono::DateTime::parse_from_str(
            &format!("{} +0000", cert.not_after),
            "%Y-%m-%d %H:%M:%S %Z %z",
        ) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => {
                // Try alternative parsing
                return Ok(());
            }
        };

        let now = Utc::now();
        let days_remaining = (expiry - now).num_days();

        // Check thresholds
        let should_alert = (days_remaining <= 1 && thresholds.expiry_1d)
            || (days_remaining <= 7 && days_remaining > 1 && thresholds.expiry_7d)
            || (days_remaining <= 14 && days_remaining > 7 && thresholds.expiry_14d)
            || (days_remaining <= 30 && days_remaining > 14 && thresholds.expiry_30d);

        if should_alert {
            let details = AlertDetails {
                certificate_serial: Some(cert.serial_number.clone()),
                certificate_issuer: Some(cert.issuer.clone()),
                certificate_expiry: Some(cert.not_after.clone()),
                previous_serial: None,
                scan_time: Utc::now(),
            };

            let alert = Alert::expiry_warning(
                identifier.to_string(),
                days_remaining,
                details,
            );

            alert_manager.send_alert(&alert).await?;
        }

        Ok(())
    }

    /// Setup signal handlers for graceful shutdown
    fn setup_signal_handlers(&self) -> Result<()> {
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};

                let mut sigterm = signal(SignalKind::terminate())
                    .expect("Failed to setup SIGTERM handler");
                let mut sigint = signal(SignalKind::interrupt())
                    .expect("Failed to setup SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        tracing::info!("Received SIGTERM");
                    }
                    _ = sigint.recv() => {
                        tracing::info!("Received SIGINT");
                    }
                }

                running.store(false, Ordering::SeqCst);
            }

            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to setup Ctrl+C handler");

                tracing::info!("Received Ctrl+C");
                running.store(false, Ordering::SeqCst);
            }
        });

        Ok(())
    }

    /// Get daemon statistics
    pub async fn stats(&self) -> DaemonStats {
        let inventory = self.inventory.lock().await;
        let scheduler = self.scheduler.lock().await;

        DaemonStats {
            total_domains: inventory.len(),
            enabled_domains: inventory.enabled_domains().len(),
            scheduled_scans: scheduler.scheduled_count(),
            alert_channels: self.alert_manager.channel_count(),
            running: self.running.load(Ordering::SeqCst),
        }
    }

    /// Test all alert channels
    pub async fn test_alerts(&self) -> Vec<(String, Result<()>)> {
        self.alert_manager.test_channels().await
    }
}

/// Daemon statistics
#[derive(Debug, Clone)]
pub struct DaemonStats {
    pub total_domains: usize,
    pub enabled_domains: usize,
    pub scheduled_scans: usize,
    pub alert_channels: usize,
    pub running: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_daemon_creation() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config).await;
        assert!(daemon.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_stats() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config).await.unwrap();

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 0);
        assert_eq!(stats.enabled_domains, 0);
        assert!(!stats.running);
    }

    #[tokio::test]
    async fn test_add_domain() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config).await.unwrap();

        let domain = MonitoredDomain::new("example.com".to_string(), 443);
        daemon.add_domain(domain).await.unwrap();

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 1);
    }
}
