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

    #[test]
    fn cleanup_cutoff_rejects_invalid_days() {
        assert!(cleanup_cutoff_days_ago(-1).is_err());
        assert!(cleanup_cutoff_days_ago(i64::MAX).is_err());
    }
}
