use crate::db::{CipherRunDatabase, ScanRecord, ScanRepository};
use chrono::{DateTime, Utc};

impl CipherRunDatabase {
    /// Get scan history for a hostname
    pub async fn get_scan_history(
        &self,
        hostname: &str,
        port: u16,
        limit: i64,
    ) -> crate::Result<Vec<ScanRecord>> {
        self.scan_repo
            .get_scans_by_hostname(hostname, port, limit)
            .await
    }

    /// Get scan history for a hostname at or after a timestamp.
    /// Results are returned in chronological order so trend analysis can consume them directly.
    pub async fn get_scan_history_since(
        &self,
        hostname: &str,
        port: u16,
        since: DateTime<Utc>,
    ) -> crate::Result<Vec<ScanRecord>> {
        let mut scans = self
            .scan_repo
            .get_scans_by_hostname_since(hostname, port, since)
            .await?;

        scans.sort_by(|a, b| {
            a.scan_timestamp
                .cmp(&b.scan_timestamp)
                .then_with(|| a.scan_id.cmp(&b.scan_id))
        });

        Ok(scans)
    }

    /// Get latest scan for a hostname
    pub async fn get_latest_scan(
        &self,
        hostname: &str,
        port: u16,
    ) -> crate::Result<Option<ScanRecord>> {
        self.scan_repo.get_latest_scan(hostname, port).await
    }

    /// Cleanup old scans based on retention policy
    pub async fn cleanup_old_scans(&self, days: i64) -> crate::Result<u64> {
        self.scan_repo.delete_old_scans(days).await
    }
}
