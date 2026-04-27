// Protocol comparison methods for ScanComparator

use super::{ProtocolDiff, ScanComparator};
use crate::db::ProtocolRecord;
use crate::db::connection::DatabasePool;
use std::collections::{BTreeMap, BTreeSet};

fn sort_protocol_names(protocols: &mut [String]) {
    protocols.sort();
}

fn normalized_protocol_name(protocol: &str) -> String {
    protocol
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '_' && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

fn protocol_identity(protocol: &str) -> String {
    let normalized = normalized_protocol_name(protocol);
    if let Some(version) = normalized.strip_prefix("TLSV") {
        format!("TLS{}", version)
    } else if let Some(version) = normalized.strip_prefix("SSLV") {
        format!("SSL{}", version)
    } else {
        normalized
    }
}

fn enabled_protocol_names_by_identity(protocols: &[ProtocolRecord]) -> BTreeMap<String, String> {
    protocols
        .iter()
        .filter(|p| p.enabled)
        .map(|p| (protocol_identity(&p.protocol_name), p.protocol_name.clone()))
        .collect()
}

impl ScanComparator {
    pub(crate) async fn compare_protocols(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<ProtocolDiff> {
        let protocols1 = self.get_protocols(scan_id_1).await?;
        let protocols2 = self.get_protocols(scan_id_2).await?;

        let protocol_names1 = enabled_protocol_names_by_identity(&protocols1);
        let protocol_names2 = enabled_protocol_names_by_identity(&protocols2);
        let set1: BTreeSet<String> = protocol_names1.keys().cloned().collect();
        let set2: BTreeSet<String> = protocol_names2.keys().cloned().collect();

        let mut added: Vec<String> = set2
            .difference(&set1)
            .filter_map(|identity| protocol_names2.get(identity).cloned())
            .collect();
        let mut removed: Vec<String> = set1
            .difference(&set2)
            .filter_map(|identity| protocol_names1.get(identity).cloned())
            .collect();
        let mut unchanged: Vec<String> = set1
            .intersection(&set2)
            .filter_map(|identity| protocol_names2.get(identity).cloned())
            .collect();

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

        let pref1_identity = pref1.as_deref().map(protocol_identity);
        let pref2_identity = pref2.as_deref().map(protocol_identity);

        let preferred_change = if pref1_identity != pref2_identity {
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
