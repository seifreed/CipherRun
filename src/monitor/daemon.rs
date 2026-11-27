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
use std::time::Instant;
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::interval;

/// Main monitoring daemon
pub struct MonitorDaemon {
    config: MonitorConfig,
    inventory: Arc<Mutex<CertificateInventory>>,
    scheduler: Arc<Mutex<SchedulingEngine>>,
    alert_manager: Arc<AlertManager>,
    detector: Arc<ChangeDetector>,
    running: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    scan_semaphore: Arc<Semaphore>,
}

#[async_trait::async_trait]
trait MonitoredCertificateClient: Send + Sync {
    async fn parse_target(&self, identifier: &str) -> Result<Target>;
    async fn fetch_leaf_certificate(&self, target: Target) -> Result<CertificateInfo>;
}

struct DefaultMonitoredCertificateClient;

#[async_trait::async_trait]
impl MonitoredCertificateClient for DefaultMonitoredCertificateClient {
    async fn parse_target(&self, identifier: &str) -> Result<Target> {
        Target::parse(identifier).await
    }

    async fn fetch_leaf_certificate(&self, target: Target) -> Result<CertificateInfo> {
        CertificateParser::new(target).get_leaf_certificate().await
    }
}

impl MonitorDaemon {
    fn log_certificate_fetch_failed(error: &crate::TlsError, duration_ms: u64) {
        tracing::error!(
            event_name = "monitor.certificate_fetch.failed",
            error_type = "TlsError",
            error_code = error.observability_code(),
            duration_ms,
            outcome = "failed",
            "Failed to fetch monitored certificate"
        );
    }

    /// Create new monitoring daemon
    pub async fn new(config: MonitorConfig) -> Result<Self> {
        let started = Instant::now();
        if let Err(error) = config.validate() {
            tracing::warn!(
                event_name = "monitor.initialization.failed",
                stage = "configuration_validation",
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                error_type = "TlsError",
                error_code = error.observability_code(),
                outcome = "failed",
                "Monitoring daemon initialization failed"
            );
            return Err(error);
        }
        let max_concurrent = config.monitor.max_concurrent_scans;
        let alert_manager = match AlertManager::from_config(&config).await {
            Ok(alert_manager) => Arc::new(alert_manager),
            Err(error) => {
                tracing::warn!(
                    event_name = "monitor.initialization.failed",
                    stage = "alert_manager",
                    duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    error_type = "TlsError",
                    error_code = error.observability_code(),
                    outcome = "failed",
                    "Monitoring daemon initialization failed"
                );
                return Err(error);
            }
        };

        Ok(Self {
            config,
            inventory: Arc::new(Mutex::new(CertificateInventory::new())),
            scheduler: Arc::new(Mutex::new(SchedulingEngine::new())),
            alert_manager,
            detector: Arc::new(ChangeDetector::new()),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
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
        let started = Instant::now();
        domain.alert_thresholds = (&self.config.monitor.thresholds).into();
        let mut inventory = self.inventory.lock().await;
        inventory.add_domain(domain)?;
        let inventory_domains = inventory.len();
        drop(inventory);

        tracing::info!(
            event_name = "monitor.inventory.domain_added",
            operation = "add_monitored_domain",
            inventory_domains,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "added",
            "Monitored domain added to inventory"
        );
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

        let started = Instant::now();
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

        if added > 0 {
            tracing::info!(
                event_name = "monitor.inventory.ct_discovered",
                operation = "allowlisted_ct_entry",
                added,
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                outcome = "updated",
                "Allowlisted CT names added to monitoring inventory"
            );
        }

        Ok(added)
    }

    /// Start the monitoring daemon
    pub async fn start(&self) -> Result<()> {
        tracing::info!(
            event_name = "monitor.starting",
            "Certificate monitoring daemon starting"
        );

        self.running.store(true, Ordering::SeqCst);

        // Setup signal handlers
        let started = Instant::now();
        if let Err(error) = self.setup_signal_handlers() {
            self.running.store(false, Ordering::SeqCst);
            tracing::error!(
                event_name = "monitor.start.failed",
                operation = "register_signal_handlers",
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                error_type = "TlsError",
                error_code = error.observability_code(),
                outcome = "failed",
                "Certificate monitoring daemon failed to start"
            );
            return Err(error);
        }

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
        tracing::info!(
            event_name = "monitor.started",
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "running",
            "Certificate monitoring daemon started"
        );

        // Main monitoring loop
        let mut tick_interval = interval(crate::constants::MONITOR_POLL_INTERVAL);

        loop {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                _ = tick_interval.tick() => {}
                _ = self.shutdown_notify.notified() => {}
            }

            if !self.running.load(Ordering::SeqCst) {
                break;
            }

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
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "stopped",
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
        self.shutdown_notify.notify_one();
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

            let task = crate::utils::task::spawn_with_current_span(async move {
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
        Self::scan_domain_with_fetcher(
            domain,
            inventory,
            alert_manager,
            detector,
            &DefaultMonitoredCertificateClient,
        )
        .await
    }

    async fn scan_domain_with_fetcher(
        domain: &MonitoredDomain,
        inventory: Arc<Mutex<CertificateInventory>>,
        alert_manager: Arc<AlertManager>,
        detector: Arc<ChangeDetector>,
        fetcher: &dyn MonitoredCertificateClient,
    ) -> Result<()> {
        let identifier = domain.identifier();
        let scan_started = std::time::Instant::now();

        tracing::debug!(
            event_name = "monitor.domain_scan.started",
            "Domain scan started"
        );

        // Parse target
        let target = match fetcher.parse_target(&identifier).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(
                    event_name = "monitor.target_validation.failed",
                    error_type = "target_validation",
                    error_code = e.observability_code(),
                    duration_ms =
                        u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX),
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
        let current_cert = match fetcher.fetch_leaf_certificate(target).await {
            Ok(cert) => cert,
            Err(e) => {
                Self::log_certificate_fetch_failed(
                    &e,
                    u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX),
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
        let shutdown_notify = Arc::clone(&self.shutdown_notify);

        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigterm = signal(SignalKind::terminate())
                .map_err(|_| crate::TlsError::Other("Failed to set up SIGTERM handler".into()))?;
            let mut sigint = signal(SignalKind::interrupt())
                .map_err(|_| crate::TlsError::Other("Failed to set up SIGINT handler".into()))?;

            crate::utils::task::spawn_with_current_span(async move {
                tokio::select! {
                    _ = sigterm.recv() => {
                        tracing::info!(event_name = "monitor.signal.received", signal = "SIGTERM");
                    }
                    _ = sigint.recv() => {
                        tracing::info!(event_name = "monitor.signal.received", signal = "SIGINT");
                    }
                }

                running.store(false, Ordering::SeqCst);
                shutdown_notify.notify_one();
            });
        }

        #[cfg(not(unix))]
        crate::utils::task::spawn_with_current_span(async move {
            if tokio::signal::ctrl_c().await.is_err() {
                tracing::error!(
                    event_name = "monitor.signal_handler.failed",
                    error_type = "signal_handler",
                    "Failed to set up Ctrl+C handler"
                );
            } else {
                tracing::info!(event_name = "monitor.signal.received", signal = "SIGINT");
            }

            running.store(false, Ordering::SeqCst);
            shutdown_notify.notify_one();
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
    use std::sync::{Arc, Mutex as StdMutex};
    use tempfile::NamedTempFile;
    use tokio::sync::Mutex as TokioMutex;
    use tracing::instrument::WithSubscriber;

    #[derive(Clone)]
    struct CapturedOutput(Arc<StdMutex<Vec<u8>>>);

    struct CapturedOutputWriter(Arc<StdMutex<Vec<u8>>>);

    impl Write for CapturedOutputWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedOutputWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedOutputWriter(self.0.clone())
        }
    }

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

    struct FixedCertificateClient {
        certificate: Option<CertificateInfo>,
    }

    #[async_trait]
    impl MonitoredCertificateClient for FixedCertificateClient {
        async fn parse_target(&self, identifier: &str) -> Result<Target> {
            let (hostname, port) = identifier
                .rsplit_once(':')
                .and_then(|(hostname, port)| port.parse::<u16>().ok().map(|port| (hostname, port)))
                .ok_or_else(|| crate::TlsError::Other("invalid test target".to_string()))?;
            Ok(Target {
                hostname: hostname.to_string(),
                port,
                ip_addresses: vec![std::net::Ipv4Addr::LOCALHOST.into()],
            })
        }

        async fn fetch_leaf_certificate(&self, _target: Target) -> Result<CertificateInfo> {
            self.certificate
                .clone()
                .ok_or_else(|| crate::TlsError::Other("certificate fetch failed".to_string()))
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
    async fn monitored_scan_with_injected_certificate_updates_inventory() {
        let domain = MonitoredDomain::new("example.com".to_string(), 443);
        let mut inventory = CertificateInventory::new();
        inventory
            .add_domain(domain.clone())
            .expect("test domain should be accepted");
        let inventory = Arc::new(Mutex::new(inventory));
        let fetcher = FixedCertificateClient {
            certificate: Some(test_certificate(
                (Utc::now() + chrono::Duration::days(90)).to_rfc3339(),
            )),
        };

        MonitorDaemon::scan_domain_with_fetcher(
            &domain,
            Arc::clone(&inventory),
            Arc::new(AlertManager::new(1).expect("valid dedup window")),
            Arc::new(ChangeDetector::new()),
            &fetcher,
        )
        .await
        .expect("successful monitored scan should complete");

        let inventory = inventory.lock().await;
        let updated = inventory
            .get_domain("example.com:443")
            .expect("domain should remain in inventory");
        assert!(updated.last_scan.is_some());
        assert_eq!(
            updated
                .last_certificate
                .as_ref()
                .map(|cert| cert.serial_number.as_str()),
            Some("123")
        );
    }

    #[tokio::test]
    async fn monitored_scan_fetch_failure_sends_failure_alert_when_enabled() {
        let mut domain = MonitoredDomain::new("example.com".to_string(), 443);
        domain.alert_thresholds.on_change = true;
        let mut inventory = CertificateInventory::new();
        inventory
            .add_domain(domain.clone())
            .expect("test domain should be accepted");
        let inventory = Arc::new(Mutex::new(inventory));
        let channel = RecordingChannel::default();
        let recorded_alerts = Arc::clone(&channel.alerts);
        let mut alert_manager = AlertManager::new(1).expect("valid dedup window");
        alert_manager.add_channel(Box::new(channel));
        let fetcher = FixedCertificateClient { certificate: None };

        MonitorDaemon::scan_domain_with_fetcher(
            &domain,
            Arc::clone(&inventory),
            Arc::new(alert_manager),
            Arc::new(ChangeDetector::new()),
            &fetcher,
        )
        .await
        .expect("certificate retrieval failure should be handled as a scan outcome");

        let alerts = recorded_alerts.lock().await;
        assert_eq!(alerts.len(), 1);
        assert!(matches!(
            alerts[0].alert_type,
            AlertType::ScanFailure { .. }
        ));
        assert!(
            inventory
                .lock()
                .await
                .get_domain("example.com:443")
                .is_some_and(|entry| entry.last_certificate.is_none())
        );
    }

    #[tokio::test]
    async fn test_alerts_reports_each_channel_result() {
        let mut daemon = MonitorDaemon::new(MonitorConfig::default())
            .await
            .expect("daemon should initialize");
        let alerts = Arc::get_mut(&mut daemon.alert_manager).expect("manager should be unique");
        alerts.add_channel(Box::new(RecordingChannel::default()));
        alerts.add_channel(Box::new(FailingChannel));

        let results = daemon.test_alerts().await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "recording");
        assert!(results[0].1.is_ok());
        assert_eq!(results[1].0, "failing");
        assert!(results[1].1.is_err());
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
    async fn test_alert_manager_initialization_failure_is_logged_safely() {
        let output = CapturedOutput(Arc::new(StdMutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(output.clone())
            .finish();
        let mut config = MonitorConfig::default();
        config.monitor.deduplication.window_hours = u64::MAX;

        let result = MonitorDaemon::new(config)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        assert!(result.is_err());
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            event["fields"]["event_name"],
            "monitor.initialization.failed"
        );
        assert_eq!(event["fields"]["stage"], "alert_manager");
        assert_eq!(event["fields"]["outcome"], "failed");
        assert!(event["fields"]["error_code"].is_string());
        assert!(event["fields"]["duration_ms"].is_number());
        assert!(!output.contains("18446744073709551615"));
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
    async fn test_start_logs_ready_before_started_and_stopped() {
        struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>, Arc<Notify>);
        struct BufferWriter(Arc<std::sync::Mutex<Vec<u8>>>, Arc<Notify>);

        impl Write for BufferWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                self.1.notify_one();
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = BufferWriter;

            fn make_writer(&'a self) -> Self::Writer {
                BufferWriter(self.0.clone(), self.1.clone())
            }
        }

        let daemon = Arc::new(
            MonitorDaemon::new(MonitorConfig::default())
                .await
                .expect("daemon should initialize"),
        );
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log_changed = Arc::new(Notify::new());
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(Buffer(output.clone(), log_changed.clone()))
            .finish();
        let start_daemon = Arc::clone(&daemon);
        let dispatch = tracing::Dispatch::new(subscriber);
        let start_task =
            tokio::spawn(async move { start_daemon.start().with_subscriber(dispatch).await });

        loop {
            let notified = log_changed.notified();
            if String::from_utf8(output.lock().unwrap().clone())
                .expect("valid JSON logs")
                .contains("monitor.started")
            {
                break;
            }
            tokio::time::timeout(std::time::Duration::from_secs(1), notified)
                .await
                .expect("daemon should reach its started event");
        }
        daemon.stop();
        tokio::time::timeout(std::time::Duration::from_secs(1), start_task)
            .await
            .expect("daemon should stop promptly")
            .expect("daemon task should join")
            .expect("daemon should stop successfully");
        assert!(!daemon.stats().await.running);

        let output = String::from_utf8(output.lock().unwrap().clone()).expect("valid JSON logs");
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("structured event"))
            .collect::<Vec<_>>();
        let event_names = events
            .iter()
            .map(|event| event["fields"]["event_name"].as_str().unwrap())
            .collect::<Vec<_>>();
        let ready_index = event_names
            .iter()
            .position(|name| *name == "monitor.inventory.ready")
            .expect("inventory should be ready");
        let started_index = event_names
            .iter()
            .position(|name| *name == "monitor.started")
            .expect("daemon should report started");
        let stopped_index = event_names
            .iter()
            .position(|name| *name == "monitor.stopped")
            .expect("daemon should report stopped");
        assert!(ready_index < started_index);
        assert!(started_index < stopped_index);
        assert_eq!(events[started_index]["fields"]["outcome"], "running");
        assert!(events[started_index]["fields"]["duration_ms"].is_number());
        assert_eq!(events[stopped_index]["fields"]["outcome"], "stopped");
        assert!(events[stopped_index]["fields"]["duration_ms"].is_number());
    }

    #[tokio::test]
    async fn test_add_domain() {
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

        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(Buffer(output.clone()))
            .finish();
        let domain = MonitoredDomain::new("example.com".to_string(), 443);
        daemon
            .add_domain(domain)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await
            .expect("test assertion should succeed");

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 1);

        let output = String::from_utf8(output.lock().unwrap().clone()).expect("valid JSON logs");
        let event: serde_json::Value =
            serde_json::from_str(output.trim()).expect("structured event");
        assert_eq!(event["level"], "INFO");
        assert_eq!(
            event["fields"]["event_name"],
            "monitor.inventory.domain_added"
        );
        assert_eq!(event["fields"]["operation"], "add_monitored_domain");
        assert_eq!(event["fields"]["inventory_domains"], 1);
        assert_eq!(event["fields"]["outcome"], "added");
        assert!(event["fields"]["duration_ms"].is_number());
        assert!(!output.contains("example.com"));
    }

    #[tokio::test]
    async fn test_ingest_ct_entry_is_allowlisted_and_deduplicated() {
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

        let mut config = MonitorConfig::default();
        config.monitor.ct_discovery_suffixes = vec!["example.com".to_string()];
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");
        let entry = ct_entry(Some("*.example.com"), &["api.example.com", "outside.test"]);
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(Buffer(output.clone()))
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);

        assert_eq!(
            daemon
                .ingest_ct_entry(&entry)
                .with_subscriber(dispatch.clone())
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            daemon
                .ingest_ct_entry(&entry)
                .with_subscriber(dispatch)
                .await
                .unwrap(),
            0
        );
        assert_eq!(daemon.stats().await.total_domains, 2);

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "{output}");
        assert_eq!(
            events[0]["fields"]["event_name"],
            "monitor.inventory.ct_discovered"
        );
        assert_eq!(events[0]["fields"]["operation"], "allowlisted_ct_entry");
        assert_eq!(events[0]["fields"]["added"], 2);
        assert_eq!(events[0]["fields"]["outcome"], "updated");
        assert!(events[0]["fields"]["duration_ms"].is_number());
        assert!(!output.contains("example.com"));
        assert!(!output.contains("outside.test"));
    }

    #[tokio::test]
    async fn ct_discovery_is_disabled_without_suffix_allowlist() {
        let daemon = MonitorDaemon::new(MonitorConfig::default())
            .await
            .expect("daemon should initialize");
        let entry = ct_entry(Some("example.com"), &[]);

        crate::ct_logs::CtEntrySink::handle_entry(&daemon, &entry)
            .await
            .expect("disabled CT discovery should be a successful no-op");

        assert_eq!(daemon.stats().await.total_domains, 0);
    }

    #[tokio::test]
    async fn test_load_domains_updates_stats() -> Result<()> {
        let config = MonitorConfig::default();
        let daemon = MonitorDaemon::new(config)
            .await
            .expect("test assertion should succeed");

        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "# Domains\nexample.com\nexample.org:8443 5m")?;

        let output = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        daemon
            .load_domains(temp_file.path())
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await?;

        let output = String::from_utf8(output.lock().unwrap().clone())?;
        let event: serde_json::Value = serde_json::from_str(output.lines().next().unwrap())?;
        assert_eq!(event["fields"]["event_name"], "monitor.inventory.loaded");
        assert_eq!(event["fields"]["domains"], 2);

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

    #[tokio::test]
    async fn closed_scan_semaphore_logs_skip_and_completes_cycle() {
        let daemon = MonitorDaemon::new(MonitorConfig::default())
            .await
            .expect("daemon should initialize");
        daemon
            .add_domain(MonitoredDomain::new("example.com".to_string(), 443))
            .await
            .expect("inventory should accept the configured domain");
        daemon.scan_semaphore.close();

        let output = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        daemon
            .run_scan_cycle()
            .with_subscriber(dispatch.clone())
            .await
            .expect("a closed scan semaphore should skip work without failing the cycle");
        daemon
            .run_scan_cycle()
            .with_subscriber(dispatch)
            .await
            .expect("a domain that is not due should be skipped without failing the cycle");

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "monitor.scan.skipped"
                && event["fields"]["error_type"] == "semaphore_closed"
                && event["fields"]["outcome"] == "skipped"
        }));
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "monitor.scan_cycle.completed"
                && event["fields"]["outcome"] == "complete"
        }));
        assert_eq!(
            events
                .iter()
                .filter(|event| event["fields"]["event_name"] == "monitor.scan_cycle.started")
                .count(),
            1
        );
        assert_eq!(daemon.stats().await.scheduled_scans, 1);
    }

    #[tokio::test]
    async fn test_scan_cycle_releases_invalid_domain_for_a_future_scan() {
        let daemon = MonitorDaemon::new(MonitorConfig::default())
            .await
            .expect("daemon should initialize");
        daemon
            .add_domain(MonitoredDomain::new("127.0.0.1".to_string(), 1))
            .await
            .expect("inventory should accept the configured domain");

        let output = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        daemon
            .run_scan_cycle()
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await
            .expect("a domain validation failure should not abort the scan cycle");

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(
            events.iter().any(|event| {
                event["fields"]["event_name"] == "monitor.target_validation.failed"
                    && event["fields"]["error_type"] == "target_validation"
                    && event["fields"]["outcome"] == "failed"
                    && event["fields"]["duration_ms"].is_number()
            }),
            "{output}"
        );
        assert!(!output.contains("127.0.0.1"));

        let stats = daemon.stats().await;
        assert_eq!(stats.total_domains, 1);
        assert_eq!(stats.scheduled_scans, 1);
        assert!(!stats.running);
    }

    #[test]
    fn monitor_failure_events_log_safe_codes_duration_and_redact_details() {
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
            runtime
                .block_on(MonitorDaemon::scan_domain_static(
                    &domain,
                    inventory,
                    alert_manager,
                    Arc::new(ChangeDetector::new()),
                ))
                .expect("invalid targets are reported without failing the daemon");
            MonitorDaemon::log_certificate_fetch_failed(
                &crate::TlsError::Other("private-certificate-error".to_string()),
                17,
            );
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "monitor.target_validation.failed"
                && event["fields"]["error_type"] == "target_validation"
                && event["fields"]["error_code"].is_string()
                && event["fields"]["duration_ms"].is_number()
                && event["fields"]["outcome"] == "failed"
        }));
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "monitor.certificate_fetch.failed"
                && event["fields"]["error_type"] == "TlsError"
                && event["fields"]["error_code"] == "other"
                && event["fields"]["duration_ms"] == 17
                && event["fields"]["outcome"] == "failed"
        }));
        assert!(!output.contains("bad:host:secret"));
        assert!(!output.contains("private-certificate-error"));
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
    async fn test_expiry_warning_obeys_disabled_and_cumulative_thresholds() {
        let channel = RecordingChannel::default();
        let recorded_alerts = Arc::clone(&channel.alerts);
        let mut alert_manager = AlertManager::new(1).expect("valid dedup window");
        alert_manager.add_channel(Box::new(channel));
        let no_thresholds = crate::monitor::types::AlertThresholds {
            expiry_30d: false,
            expiry_14d: false,
            expiry_7d: false,
            expiry_1d: false,
            on_change: false,
        };
        let date_threshold = crate::monitor::types::AlertThresholds {
            expiry_30d: true,
            ..no_thresholds.clone()
        };

        MonitorDaemon::check_expiry_warnings(
            "disabled.example:443",
            &test_certificate("not-a-date".to_string()),
            &no_thresholds,
            &alert_manager,
        )
        .await
        .expect("disabled expiry alerts should tolerate an invalid date");
        MonitorDaemon::check_expiry_warnings(
            "outside.example:443",
            &test_certificate((Utc::now() + chrono::Duration::days(45)).to_rfc3339()),
            &date_threshold,
            &alert_manager,
        )
        .await
        .expect("a certificate beyond the configured window should not alert");
        assert!(recorded_alerts.lock().await.is_empty());

        MonitorDaemon::check_expiry_warnings(
            "inside.example:443",
            &test_certificate((Utc::now() + chrono::Duration::days(10)).to_rfc3339()),
            &date_threshold,
            &alert_manager,
        )
        .await
        .expect("the cumulative 30-day threshold should alert within its window");
        let alerts = recorded_alerts.lock().await;
        assert_eq!(alerts.len(), 1);
        assert!(matches!(
            alerts[0].alert_type,
            AlertType::ExpiryWarning { .. }
        ));
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
