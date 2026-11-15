// Monitoring Daemon - Main orchestration

use crate::Result;
use crate::certificates::parser::{CertificateInfo, CertificateParser};
use crate::certificates::validator::parse_cert_date;
use crate::ct_logs::{CtEntrySink, CtLogEntry};
use crate::monitor::alerts::{Alert, AlertDetails, AlertManager};
use crate::monitor::config::MonitorConfig;
use crate::monitor::detector::ChangeDetector;
use crate::monitor::inventory::{CertificateInventory, MonitoredDomain};
use crate::monitor::scheduler::SchedulingEngine;
use crate::security::input_validation::looks_like_dotted_ip_literal;
use crate::security::validate_hostname;
use crate::utils::network::Target;
use chrono::Utc;
use std::path::Path;
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
        config.validate()?;
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
    pub async fn load_domains(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut inventory = self.inventory.lock().await;
        inventory.load_from_file(path, self.config.monitor.default_interval_seconds)?;
        // The file format has no per-domain thresholds, so apply the configured
        // ones; otherwise the [thresholds] config section would be ignored.
        inventory.apply_default_thresholds(&(&self.config.monitor.thresholds).into());
        tracing::info!(
            event_name = "monitor.inventory.loaded",
            domains = inventory.len(),
            "Monitoring inventory loaded"
        );
        Ok(())
    }

    /// Add a single domain, applying the configured alert thresholds.
    pub async fn add_domain(&self, mut domain: MonitoredDomain) -> Result<()> {
        domain.alert_thresholds = (&self.config.monitor.thresholds).into();
        let mut inventory = self.inventory.lock().await;
        inventory.add_domain(domain)?;
        Ok(())
    }

    /// Add newly observed CT names to the monitored inventory.
    ///
    /// Discovery is opt-in: an empty suffix allowlist accepts no CT names.
    pub async fn ingest_ct_entry(&self, entry: &CtLogEntry) -> Result<usize> {
        let suffixes: Vec<String> = self
            .config
            .monitor
            .ct_discovery_suffixes
            .iter()
            .map(|suffix| suffix.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        if suffixes.is_empty() {
            return Ok(0);
        }

        let mut names = std::collections::BTreeSet::new();
        if let Some(common_name) = &entry.certificate.subject_cn {
            names.insert(common_name.clone());
        }
        names.extend(entry.certificate.subject_an.iter().cloned());

        let mut inventory = self.inventory.lock().await;
        let mut added = 0;
        for raw_name in names {
            let name = raw_name
                .trim()
                .trim_end_matches('.')
                .strip_prefix("*.")
                .unwrap_or(raw_name.trim().trim_end_matches('.'))
                .to_ascii_lowercase();
            if name.is_empty()
                || looks_like_dotted_ip_literal(&name)
                || validate_hostname(&name).is_err()
                || !suffixes
                    .iter()
                    .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
            {
                continue;
            }
            if inventory.get_domain(&name).is_some() {
                continue;
            }
            let mut domain = MonitoredDomain::new(name, 443)
                .with_interval(self.config.monitor.default_interval_seconds);
            domain.alert_thresholds = (&self.config.monitor.thresholds).into();
            inventory.add_domain(domain)?;
            added += 1;
        }

        Ok(added)
    }

    /// Start the monitoring daemon
    pub async fn start(&self) -> Result<()> {
        tracing::info!(
            event_name = "monitor.started",
            "Certificate monitoring daemon started"
        );

        self.running.store(true, Ordering::SeqCst);

        // Setup signal handlers
        self.setup_signal_handlers()?;

        // Log configuration
        let inventory = self.inventory.lock().await;
        let enabled_count = inventory.enabled_domains().len();
        drop(inventory);

        tracing::info!(
            event_name = "monitor.inventory.ready",
            domains = enabled_count,
            "Monitoring inventory ready"
        );
        tracing::info!(
            event_name = "monitor.configuration.loaded",
            alert_channels = ?self.config.enabled_channels(),
            concurrency = self.config.monitor.max_concurrent_scans,
            "Monitoring configuration loaded"
        );

        // Main monitoring loop
        let mut tick_interval = interval(crate::constants::MONITOR_POLL_INTERVAL);

        while self.running.load(Ordering::SeqCst) {
            tick_interval.tick().await;

            if let Err(error) = self.run_scan_cycle().await {
                tracing::error!(
                    event_name = "monitor.scan_cycle.failed",
                    error_type = "TlsError",
                    error_code = error.observability_code(),
                    outcome = "failed",
                    "Monitoring scan cycle failed"
                );
            }
        }

        tracing::info!(
            event_name = "monitor.stopped",
            "Certificate monitoring daemon stopped"
        );
        Ok(())
    }

    /// Stop the daemon
    pub fn stop(&self) {
        tracing::info!(
            event_name = "monitor.shutdown_requested",
            "Monitoring shutdown requested"
        );
        self.running.store(false, Ordering::SeqCst);
    }

    /// Run a single scan cycle
    async fn run_scan_cycle(&self) -> Result<()> {
        let cycle_started = std::time::Instant::now();
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

        tracing::info!(
            event_name = "monitor.scan_cycle.started",
            domains = due_count,
            "Monitoring scan cycle started"
        );

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
                            event_name = "monitor.scan.skipped",
                            error_type = "semaphore_closed",
                            outcome = "skipped",
                            "Skipping monitoring scan"
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
                Ok(Err(error)) => tracing::error!(
                    event_name = "monitor.domain_scan.failed",
                    error_type = "TlsError",
                    error_code = error.observability_code(),
                    outcome = "failed",
                    "Domain scan failed"
                ),
                Err(error) => tracing::error!(
                    event_name = "monitor.domain_scan.task_failed",
                    error_type = "JoinError",
                    error_code = if error.is_cancelled() {
                        "cancelled"
                    } else if error.is_panic() {
                        "panic"
                    } else {
                        "other"
                    },
                    outcome = "failed",
                    "Domain scan task failed"
                ),
            }

            // Always clear in-progress and schedule next scan
            // (on failure, this allows the domain to be retried next cycle)
            let mut scheduler = self.scheduler.lock().await;
            scheduler.mark_scan_completed(domain)?;
        }

        tracing::info!(
            event_name = "monitor.scan_cycle.completed",
            domains = due_count,
            duration_ms = u64::try_from(cycle_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "complete",
            "Monitoring scan cycle completed"
        );

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
        let scan_started = std::time::Instant::now();

        tracing::debug!(
            event_name = "monitor.domain_scan.started",
            "Domain scan started"
        );

        // Parse target
        let target = match Target::parse(&identifier).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(
                    event_name = "monitor.target_validation.failed",
                    error_type = "target_validation",
                    error_code = e.observability_code(),
                    outcome = "failed",
                    "Monitoring target validation failed"
                );

                let alert = Alert::scan_failure(
                    identifier.clone(),
                    format!("Failed to parse target: {}", e),
                );

                // AlertManager logs per-channel failures; don't duplicate them here.
                let _ = alert_manager.send_alert(&alert).await;

                return Ok(());
            }
        };

        // Get certificate
        let parser = CertificateParser::new(target);

        let current_cert = match parser.get_leaf_certificate().await {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!(
                    event_name = "monitor.certificate_fetch.failed",
                    error_type = "TlsError",
                    error_code = e.observability_code(),
                    outcome = "failed",
                    "Failed to fetch monitored certificate"
                );

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

                    let _ = alert_manager.send_alert(&alert).await;
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
                tracing::info!(
                    event_name = "monitor.certificate_changes.detected",
                    changes = changes.len(),
                    "Certificate changes detected"
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

                    let alert = Alert::certificate_change(identifier.clone(), changes, details);

                    let _ = alert_manager.send_alert(&alert).await;
                }
            }
        }

        // Check expiry warnings (don't propagate alert errors to avoid skipping inventory update)
        if let Err(error) = Self::check_expiry_warnings(
            &identifier,
            &current_cert,
            &domain.alert_thresholds,
            &alert_manager,
        )
        .await
        {
            tracing::error!(
                event_name = "monitor.expiry_check.failed",
                error_type = "expiry_check",
                error_code = error.observability_code(),
                "Failed to check certificate expiry"
            );
        }

        // Re-acquire lock to update inventory
        let mut inventory_guard = inventory.lock().await;
        if let Some(domain_mut) = inventory_guard.get_domain_mut(&identifier) {
            domain_mut.update_scan(Some(current_cert));
        }

        tracing::debug!(
            event_name = "monitor.domain_scan.completed",
            duration_ms = u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "complete",
            "Domain scan completed"
        );

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
                    event_name = "monitor.certificate_expiry.parse_failed",
                    error_type = "certificate_expiry",
                    "Failed to parse certificate expiry date"
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
                    alert_manager.send_alert(&alert).await?;
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
                    Err(_) => {
                        tracing::error!(
                            event_name = "monitor.signal_handler.setup_failed",
                            error_type = "signal_handler",
                            signal = "SIGTERM",
                            "Failed to set up signal handler"
                        );
                        return;
                    }
                };
                let mut sigint = match signal(SignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(_) => {
                        tracing::error!(
                            event_name = "monitor.signal_handler.setup_failed",
                            error_type = "signal_handler",
                            signal = "SIGINT",
                            "Failed to set up signal handler"
                        );
                        return;
                    }
                };

                tokio::select! {
                    _ = sigterm.recv() => {
                        tracing::info!(event_name = "monitor.signal.received", signal = "SIGTERM");
                    }
                    _ = sigint.recv() => {
                        tracing::info!(event_name = "monitor.signal.received", signal = "SIGINT");
                    }
                }

                running.store(false, Ordering::SeqCst);
            }

            #[cfg(not(unix))]
            {
                if tokio::signal::ctrl_c().await.is_err() {
                    tracing::error!(
                        event_name = "monitor.signal_handler.failed",
                        error_type = "signal_handler",
                        "Failed to setup Ctrl+C handler"
                    );
                    return;
                }

                tracing::info!(event_name = "monitor.signal.received", signal = "SIGINT");
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

#[async_trait::async_trait]
impl CtEntrySink for MonitorDaemon {
    async fn handle_entry(&self, entry: &CtLogEntry) -> crate::ct_logs::Result<()> {
        self.ingest_ct_entry(entry).await.map(|_| ())
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

    struct FailingChannel;

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

    #[async_trait]
    impl AlertChannel for FailingChannel {
        async fn send_alert(&self, _alert: &Alert) -> Result<()> {
            Err(crate::TlsError::Other("channel failed".to_string()))
        }

        fn channel_name(&self) -> &str {
            "failing"
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

    fn ct_entry(subject_cn: Option<&str>, subject_an: &[&str]) -> CtLogEntry {
        CtLogEntry {
            log_source: "test-log".to_string(),
            index: 7,
            timestamp: Utc::now(),
            cert_type: crate::ct_logs::CertType::X509Certificate,
            certificate: crate::ct_logs::parser::Certificate {
                der: Vec::new(),
                subject_cn: subject_cn.map(str::to_string),
                subject_an: subject_an.iter().map(|name| (*name).to_string()).collect(),
                issuer_cn: Some("Test CA".to_string()),
                not_before: Utc::now(),
                not_after: Utc::now(),
                serial: "1".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_daemon_creation() {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config).await;
        assert!(daemon.is_ok());
    }

    #[tokio::test]
    async fn test_daemon_rejects_invalid_direct_config() {
        let mut config = MonitorConfig::default();
        config.monitor.max_concurrent_scans = 0;

        let err = match MonitorDaemon::new(config).await {
            Ok(_) => panic!("invalid direct config should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("max_concurrent_scans"));
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
    async fn test_ingest_ct_entry_is_allowlisted_and_deduplicated() {
        let mut config = MonitorConfig::default();
        config.monitor.ct_discovery_suffixes = vec!["example.com".to_string()];
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");
        let entry = ct_entry(Some("*.example.com"), &["api.example.com", "outside.test"]);

        assert_eq!(daemon.ingest_ct_entry(&entry).await.unwrap(), 2);
        assert_eq!(daemon.ingest_ct_entry(&entry).await.unwrap(), 0);
        assert_eq!(daemon.stats().await.total_domains, 2);
    }

    #[tokio::test]
    async fn test_load_domains_updates_stats() -> Result<()> {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "# Domains\nexample.com\nexample.org:8443 5m")?;

        daemon.load_domains(temp_file.path()).await?;

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 2);
        assert_eq!(stats.enabled_domains, 2);

        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_load_domains_does_not_pre_reject_non_utf8_path() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join(OsString::from_vec(vec![
            b'd', b'o', b'm', b'a', b'i', b'n', b's', 0xff, b'.', b't', b'x', b't',
        ]));

        let err = daemon
            .load_domains(&path)
            .await
            .expect_err("missing non-UTF-8 path should produce a filesystem error");

        assert!(!err.to_string().contains("Invalid domains file path"));
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

    #[test]
    fn failed_monitor_scan_logs_safe_error_codes() {
        struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
        struct BufferWriter(Arc<std::sync::Mutex<Vec<u8>>>);

        impl Write for BufferWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = BufferWriter;

            fn make_writer(&'a self) -> Self::Writer {
                BufferWriter(self.0.clone())
            }
        }

        let domain = MonitoredDomain::new("bad:host:secret".to_string(), 443);
        let inventory = Arc::new(Mutex::new(CertificateInventory::new()));
        let mut alert_manager = AlertManager::new(1).expect("valid dedup window");
        alert_manager.add_channel(Box::new(FailingChannel));
        let alert_manager = Arc::new(alert_manager);
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(Buffer(output.clone()))
            .finish();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime should build");

        tracing::subscriber::with_default(subscriber, || {
            runtime.block_on(MonitorDaemon::scan_domain_static(
                &domain,
                inventory,
                alert_manager,
                Arc::new(ChangeDetector::new()),
            ))
        })
        .expect("invalid targets are reported without failing the daemon");

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "monitor.target_validation.failed"
                && event["fields"]["error_type"] == "target_validation"
                && event["fields"]["error_code"].is_string()
                && event["fields"]["outcome"] == "failed"
        }));
        assert!(!output.contains("bad:host:secret"));
        assert!(!output.contains("channel failed"));
    }

    #[tokio::test]
    async fn test_expiry_warning_treats_recently_expired_certificate_as_expired() {
        let channel = RecordingChannel::default();
        let recorded_alerts = Arc::clone(&channel.alerts);
        let mut alert_manager = AlertManager::new(1).expect("valid dedup window");
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
    async fn test_unparseable_expiry_propagates_alert_failure() {
        let mut alert_manager = AlertManager::new(1).expect("valid dedup window");
        alert_manager.add_channel(Box::new(FailingChannel));
        let thresholds = crate::monitor::types::AlertThresholds {
            expiry_30d: true,
            expiry_14d: false,
            expiry_7d: false,
            expiry_1d: false,
            on_change: false,
        };
        let cert = test_certificate("not-a-date".to_string());

        let err = MonitorDaemon::check_expiry_warnings(
            "example.com:443",
            &cert,
            &thresholds,
            &alert_manager,
        )
        .await
        .expect_err("failed alert delivery should be reported");

        assert!(err.to_string().contains("All alert channels failed"));
    }

    #[tokio::test]
    async fn test_load_domains_empty_file() -> Result<()> {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let temp_file = NamedTempFile::new()?;
        daemon.load_domains(temp_file.path()).await?;

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 0);
        assert_eq!(stats.enabled_domains, 0);
        Ok(())
    }
}
