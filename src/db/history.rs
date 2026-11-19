use crate::TlsError;
use crate::db::{CipherRunDatabase, ScanRecord, ScanRepository};
use chrono::{DateTime, Duration, Utc};

pub(crate) fn cleanup_cutoff_days_ago(days: i64) -> crate::Result<DateTime<Utc>> {
    if days < 0 {
        return Err(TlsError::InvalidInput {
            message: format!("Cleanup days cannot be negative: {}", days),
        });
    }
    let duration = Duration::try_days(days).ok_or_else(|| TlsError::InvalidInput {
        message: format!("Cleanup days value is too large: {}", days),
    })?;
    Utc::now()
        .checked_sub_signed(duration)
        .ok_or_else(|| TlsError::InvalidInput {
            message: format!("Cleanup days value is too large: {}", days),
        })
}

impl CipherRunDatabase {
    /// Get scan history for a hostname
    pub async fn get_scan_history(
        &self,
        hostname: &str,
        port: u16,
        limit: i64,
    ) -> crate::Result<Vec<ScanRecord>> {
        if limit <= 0 {
            return Err(TlsError::InvalidInput {
                message: format!("History limit must be positive: {}", limit),
            });
        }

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

        // Ascending by timestamp, tie-broken by ascending scan_id so the sequence
        // is truly chronological: within a same-timestamp group the later-inserted
        // (higher scan_id) row sorts last. Consumers that take `.last()` as "latest"
        // (e.g. the dashboard summary) then correctly see the newest scan.
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
        cleanup_cutoff_days_ago(days)?;

        self.scan_repo.delete_old_scans(days).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_database() -> (CipherRunDatabase, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("temporary database directory should exist");
        let config = crate::db::DatabaseConfig::sqlite(directory.path().join("history.db"));
        let database = CipherRunDatabase::new(&config)
            .await
            .expect("test database should initialize");
        (database, directory)
    }

    #[test]
    fn cleanup_cutoff_rejects_invalid_days() {
        assert!(cleanup_cutoff_days_ago(-1).is_err());
        assert!(cleanup_cutoff_days_ago(i64::MAX).is_err());
        assert!(cleanup_cutoff_days_ago(100_000_000_000).is_err());
    }

    #[tokio::test]
    async fn history_rejects_nonpositive_limits() {
        let (database, _directory) = test_database().await;

        assert!(
            database
                .get_scan_history("example.com", 443, 0)
                .await
                .is_err()
        );
        database.close().await;
    }

    #[tokio::test]
    async fn history_orders_equal_timestamps_by_scan_id_and_returns_latest() {
        let (database, _directory) = test_database().await;
        let timestamp = Utc::now();
        let mut first = ScanRecord::new("example.com".to_string(), 443);
        first.scan_timestamp = timestamp;
        let mut second = ScanRecord::new("example.com".to_string(), 443);
        second.scan_timestamp = timestamp;
        let first_id = database
            .scan_repo
            .create_scan(&first)
            .await
            .expect("first scan should persist");
        let second_id = database
            .scan_repo
            .create_scan(&second)
            .await
            .expect("second scan should persist");

        let scans = database
            .get_scan_history_since("example.com", 443, timestamp)
            .await
            .expect("history should load");
        assert_eq!(
            scans.iter().map(|scan| scan.scan_id).collect::<Vec<_>>(),
            [Some(first_id), Some(second_id)]
        );
        assert_eq!(
            database
                .get_latest_scan("example.com", 443)
                .await
                .expect("latest scan should load")
                .and_then(|scan| scan.scan_id),
            Some(second_id)
        );

        database.close().await;
    }
}
