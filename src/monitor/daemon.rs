// Monitoring Daemon - Main orchestration

use crate::Result;
use crate::certificates::parser::{CertificateInfo, CertificateParser};
use crate::certificates::validator::parse_cert_date;
use crate::monitor::alerts::{Alert, AlertDetails, AlertManager};
use crate::monitor::config::MonitorConfig;
use crate::monitor::detector::ChangeDetector;
use crate::monitor::inventory::{CertificateInventory, MonitoredDomain};
use crate::monitor::scheduler::SchedulingEngine;
use crate::utils::network::Target;
use chrono::Utc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

        tracing::info!("Monitoring {} enabled domains", enabled_count);
        tracing::info!(
            "Alert channels: {}",
            self.config.enabled_channels().join(", ")
        );
        tracing::info!(
            "Max concurrent scans: {}",
            self.config.monitor.max_concurrent_scans
        );

        // Main monitoring loop
        let mut tick_interval = interval(crate::constants::MONITOR_POLL_INTERVAL);

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

        // Clone domains that need scanning (necessary for async task ownership)
        let domains_to_check: Vec<MonitoredDomain> = enabled_domains.into_iter().cloned().collect();
        drop(inventory);

        // Get domains due for scanning and mark them in-progress atomically
        // to prevent concurrent scan cycles from picking up the same domains
        let mut scheduler = self.scheduler.lock().await;
        let due_domains = scheduler.get_domains_to_scan(&domains_to_check);
        for domain in &due_domains {
            scheduler.mark_scan_in_progress(domain);
        }
        let due_count = due_domains.len();
        drop(scheduler);

        if due_count == 0 {
            return Ok(());
        }

        tracing::info!("Scanning {} domains", due_count);

        // Scan domains concurrently (limited by semaphore)
        // Acquire permits BEFORE spawning tasks to truly limit concurrency.
        // This ensures no more than max_concurrent_scans run simultaneously.
        let mut tasks = Vec::new();

        for domain in due_domains {
            let domain_clone = domain.clone();
            let inventory_clone = Arc::clone(&self.inventory);
            let alert_manager_clone = Arc::clone(&self.alert_manager);
            let detector_clone = Arc::clone(&self.detector);
            let semaphore_clone = Arc::clone(&self.scan_semaphore);

            let task = tokio::spawn(async move {
                // Acquire semaphore permit - abort scan if semaphore is closed
                let _permit = match semaphore_clone.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(
                            "Semaphore closed, skipping scan for {}",
                            domain_clone.identifier()
                        );
                        return Ok(());
                    }
                };

                Self::scan_domain_static(
                    &domain_clone,
                    inventory_clone,
                    alert_manager_clone,
                    detector_clone,
                )
                .await
            });

            tasks.push((domain, task));
        }

        // Wait for all scans to complete
        for (domain, task) in tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::error!("Scan error: {}", e),
                Err(e) => tracing::error!("Scan task panicked: {}", e),
            }

            // Always clear in-progress and schedule next scan
            // (on failure, this allows the domain to be retried next cycle)
            let mut scheduler = self.scheduler.lock().await;
            scheduler.mark_scan_completed(domain);
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

                // Send scan failure alert if any monitoring threshold is enabled
                if domain.alert_thresholds.on_change
                    || domain.alert_thresholds.expiry_1d
                    || domain.alert_thresholds.expiry_7d
                    || domain.alert_thresholds.expiry_14d
                    || domain.alert_thresholds.expiry_30d
                {
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

        // Get previous certificate from inventory (brief lock)
        let previous_cert = {
            let inventory_guard = inventory.lock().await;
            inventory_guard
                .get_domain(&identifier)
                .and_then(|d| d.last_certificate.as_ref())
                .cloned()
        };

        // Detect changes and send alerts WITHOUT holding the lock
        if let Some(prev) = previous_cert {
            let changes = detector.detect_changes(&prev, &current_cert);

            if !changes.is_empty() {
                tracing::info!("Detected {} changes for {}", changes.len(), identifier);

                // Send change alert if configured
                if domain.alert_thresholds.on_change {
                    let details = AlertDetails {
                        certificate_serial: Some(current_cert.serial_number.clone()),
                        certificate_issuer: Some(current_cert.issuer.clone()),
                        certificate_expiry: Some(current_cert.not_after.clone()),
                        previous_serial: Some(prev.serial_number.clone()),
                        scan_time: Utc::now(),
                    };

                    let alert = Alert::certificate_change(identifier.clone(), changes, details);

                    if let Err(e) = alert_manager.send_alert(&alert).await {
                        tracing::error!("Failed to send change alert: {}", e);
                    }
                }
            }
        }

        // Check expiry warnings (don't propagate alert errors to avoid skipping inventory update)
        if let Err(e) = Self::check_expiry_warnings(
            &identifier,
            &current_cert,
            &domain.alert_thresholds,
            &alert_manager,
        )
        .await
        {
            tracing::error!("Failed to check expiry warnings for {}: {}", identifier, e);
        }

        // Re-acquire lock to update inventory
        let mut inventory_guard = inventory.lock().await;
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
        let expiry = match parse_cert_date(&cert.not_after) {
            Some(dt) => dt,
            None => {
                tracing::warn!(
                    "Failed to parse certificate expiry date for {} (input was: {})",
                    identifier,
                    cert.not_after
                );
                // Alert on unparseable date if expiry warnings are enabled
                if thresholds.expiry_1d
                    || thresholds.expiry_7d
                    || thresholds.expiry_14d
                    || thresholds.expiry_30d
                {
                    let alert = Alert::scan_failure(
                        identifier.to_string(),
                        format!(
                            "Certificate has unparseable expiry date: {}",
                            cert.not_after
                        ),
                    );
                    let _ = alert_manager.send_alert(&alert).await;
                }
                return Ok(());
            }
        };

        let now = Utc::now();

        // Already expired certificates — generate critical alert (only if any expiry threshold enabled)
        if now > expiry {
            let any_expiry_threshold = thresholds.expiry_1d
                || thresholds.expiry_7d
                || thresholds.expiry_14d
                || thresholds.expiry_30d;
            if !any_expiry_threshold {
                return Ok(());
            }

            let days_remaining = -(now - expiry).num_days().max(1);

            let details = AlertDetails {
                certificate_serial: Some(cert.serial_number.clone()),
                certificate_issuer: Some(cert.issuer.clone()),
                certificate_expiry: Some(cert.not_after.clone()),
                previous_serial: None,
                scan_time: Utc::now(),
            };

            let alert = Alert::expiry_warning(identifier.to_string(), days_remaining, details);
            alert_manager.send_alert(&alert).await?;
            return Ok(());
        }

        let days_remaining = (expiry - now).num_days();

        // Check thresholds with cumulative matching: each threshold covers its
        // full range so that enabling expiry_30d alerts for ALL certs expiring
        // within 30 days, not just those between 15-30 days.
        let should_alert = (days_remaining <= 1 && thresholds.expiry_1d)
            || (days_remaining <= 7 && thresholds.expiry_7d)
            || (days_remaining <= 14 && thresholds.expiry_14d)
            || (days_remaining <= 30 && thresholds.expiry_30d);

        if should_alert {
            let details = AlertDetails {
                certificate_serial: Some(cert.serial_number.clone()),
                certificate_issuer: Some(cert.issuer.clone()),
                certificate_expiry: Some(cert.not_after.clone()),
                previous_serial: None,
                scan_time: Utc::now(),
            };

            let alert = Alert::expiry_warning(identifier.to_string(), days_remaining, details);

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
                use tokio::signal::unix::{SignalKind, signal};

                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("Failed to setup SIGTERM handler: {}", e);
                        return;
                    }
                };
                let mut sigint = match signal(SignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("Failed to setup SIGINT handler: {}", e);
                        return;
                    }
                };

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
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::error!("Failed to setup Ctrl+C handler: {}", e);
                    return;
                }

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
    use crate::monitor::alerts::{AlertChannel, AlertType};
    use crate::monitor::detector::ChangeSeverity;
    use async_trait::async_trait;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::Mutex as TokioMutex;

    #[derive(Clone, Default)]
    struct RecordingChannel {
        alerts: Arc<TokioMutex<Vec<Alert>>>,
    }

    #[async_trait]
    impl AlertChannel for RecordingChannel {
        async fn send_alert(&self, alert: &Alert) -> Result<()> {
            self.alerts.lock().await.push(alert.clone());
            Ok(())
        }

        fn channel_name(&self) -> &str {
            "recording"
        }
    }

    fn test_certificate(not_after: String) -> CertificateInfo {
        CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_daemon_creation() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config).await;
        assert!(daemon.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_stats() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 0);
        assert_eq!(stats.enabled_domains, 0);
        assert!(!stats.running);
    }

    #[tokio::test]
    async fn test_add_domain() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let domain = MonitoredDomain::new("example.com".to_string(), 443);
        daemon
            .add_domain(domain)
            .await
            .expect("test assertion should succeed");

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 1);
    }

    #[tokio::test]
    async fn test_load_domains_updates_stats() -> Result<()> {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "# Domains\nexample.com\nexample.org:8443 5m")?;

        daemon
            .load_domains(
                temp_file
                    .path()
                    .to_str()
                    .expect("temp file path should be valid UTF-8"),
            )
            .await?;

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 2);
        assert_eq!(stats.enabled_domains, 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_daemon_stop_flag() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        daemon.stop();
        let stats = daemon.stats().await;
        assert!(!stats.running);
    }

    #[tokio::test]
    async fn test_run_scan_cycle_no_domains() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        daemon.run_scan_cycle().await.expect("scan cycle ok");
    }

    #[tokio::test]
    async fn test_expiry_warning_treats_recently_expired_certificate_as_expired() {
        let channel = RecordingChannel::default();
        let recorded_alerts = Arc::clone(&channel.alerts);
        let mut alert_manager = AlertManager::new(0);
        alert_manager.add_channel(Box::new(channel));
        let thresholds = crate::monitor::types::AlertThresholds {
            expiry_30d: false,
            expiry_14d: false,
            expiry_7d: false,
            expiry_1d: true,
            on_change: false,
        };
        let cert = test_certificate((Utc::now() - chrono::Duration::minutes(5)).to_rfc3339());

        MonitorDaemon::check_expiry_warnings("example.com:443", &cert, &thresholds, &alert_manager)
            .await
            .expect("expiry warning check should succeed");

        let alerts = recorded_alerts.lock().await;
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.severity, ChangeSeverity::Critical);
        assert!(
            alert.message.contains("expired"),
            "unexpected alert message: {}",
            alert.message
        );
        match alert.alert_type {
            AlertType::ExpiryWarning { days_remaining } => assert!(
                days_remaining < 0,
                "expected negative days_remaining for expired cert, got {days_remaining}"
            ),
            _ => panic!("expected expiry warning alert, got {:?}", alert.alert_type),
        }
    }

    #[tokio::test]
    async fn test_load_domains_empty_file() -> Result<()> {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let temp_file = NamedTempFile::new()?;
        daemon
            .load_domains(
                temp_file
                    .path()
                    .to_str()
                    .expect("temp file path should be valid UTF-8"),
            )
            .await?;

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 0);
        assert_eq!(stats.enabled_domains, 0);
        Ok(())
    }
}
