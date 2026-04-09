// Protocol comparison methods for ScanComparator

use super::{ProtocolDiff, ScanComparator};
use crate::db::ProtocolRecord;
use crate::db::connection::DatabasePool;
use std::collections::HashSet;

fn sort_protocol_names(protocols: &mut Vec<String>) {
    protocols.sort();
}

impl ScanComparator {
    pub(crate) async fn compare_protocols(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<ProtocolDiff> {
        let protocols1 = self.get_protocols(scan_id_1).await?;
        let protocols2 = self.get_protocols(scan_id_2).await?;

        // Use references in HashSet to avoid cloning
        let set1: HashSet<&str> = protocols1
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.protocol_name.as_str())
            .collect();
        let set2: HashSet<&str> = protocols2
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.protocol_name.as_str())
            .collect();

        // Only clone when building final result vectors
        let mut added: Vec<String> = set2.difference(&set1).map(|s| s.to_string()).collect();
        let mut removed: Vec<String> = set1.difference(&set2).map(|s| s.to_string()).collect();
        let mut unchanged: Vec<String> = set1.intersection(&set2).map(|s| s.to_string()).collect();

        sort_protocol_names(&mut added);
        sort_protocol_names(&mut removed);
        sort_protocol_names(&mut unchanged);

        let pref1 = protocols1
            .iter()
            .find(|p| p.preferred)
            .map(|p| p.protocol_name.clone()); // Necessary: for return value
        let pref2 = protocols2
            .iter()
            .find(|p| p.preferred)
            .map(|p| p.protocol_name.clone()); // Necessary: for return value

        let preferred_change = if pref1 != pref2 {
            Some((pref1, pref2))
        } else {
            None
        };

        Ok(ProtocolDiff {
            added,
            removed,
            unchanged,
            preferred_change,
        })
    }

    async fn get_protocols(&self, scan_id: i64) -> crate::Result<Vec<ProtocolRecord>> {
        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let protocols = sqlx::query_as::<_, ProtocolRecord>(
                    "SELECT protocol_id, scan_id, protocol_name, enabled, preferred FROM protocols WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch protocols: {}", e)))?;
                Ok(protocols)
            }
            DatabasePool::Sqlite(pool) => {
                let protocols = sqlx::query_as::<_, ProtocolRecord>(
                    "SELECT protocol_id, scan_id, protocol_name, enabled, preferred FROM protocols WHERE scan_id = ?"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch protocols: {}", e)))?;
                Ok(protocols)
            }
        }
    }
}
