// Protocol comparison methods for ScanComparator

use super::{ProtocolDiff, ScanComparator};
use crate::db::ProtocolRecord;
use crate::db::analytics::protocol_identity::protocol_identity;
use crate::db::connection::DatabasePool;
use std::collections::{BTreeMap, BTreeSet};

fn sort_protocol_names(protocols: &mut [String]) {
    protocols.sort();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BindValue;
    use crate::db::analytics::test_support::{insert_scan, setup_db};
    use chrono::Utc;

    async fn insert_protocol(
        db: &crate::db::CipherRunDatabase,
        scan_id: i64,
        name: &str,
        enabled: bool,
        preferred: bool,
    ) {
        let mut query_builder = db.pool().query_builder();
        let query = query_builder.insert_query(
            "protocols",
            &["scan_id", "protocol_name", "enabled", "preferred"],
        );
        db.pool()
            .execute(
                &query,
                vec![
                    BindValue::Int64(scan_id),
                    BindValue::String(name.to_string()),
                    BindValue::Bool(enabled),
                    BindValue::Bool(preferred),
                ],
            )
            .await
            .expect("protocol record should insert");
    }

    #[tokio::test]
    async fn compares_enabled_protocols_by_identity_and_preference() {
        let db = setup_db("scan-comparator-protocols").await;
        let first = insert_scan(&db, "example.test", 443, Utc::now(), None, None).await;
        let second = insert_scan(&db, "example.test", 443, Utc::now(), None, None).await;

        insert_protocol(&db, first, "TLS 1.2", true, true).await;
        insert_protocol(&db, first, "TLS 1.0", true, false).await;
        insert_protocol(&db, first, "SSLv3", false, false).await;
        insert_protocol(&db, second, "TLSv1.2", true, false).await;
        insert_protocol(&db, second, "TLS 1.3", true, true).await;
        insert_protocol(&db, second, "TLS 1.1", true, false).await;
        insert_protocol(&db, second, "TLS 1.0", false, false).await;

        let diff = ScanComparator::new(db)
            .compare_protocols(first, second)
            .await
            .expect("protocols should compare");

        assert_eq!(diff.added, ["TLS 1.1", "TLS 1.3"]);
        assert_eq!(diff.removed, ["TLS 1.0"]);
        assert_eq!(diff.unchanged, ["TLSv1.2"]);
        assert_eq!(
            diff.preferred_change,
            Some((Some("TLS 1.2".to_string()), Some("TLS 1.3".to_string())))
        );
    }

    #[tokio::test]
    async fn reports_protocol_query_failures_with_context() {
        let db = setup_db("scan-comparator-protocol-query-error").await;
        let crate::db::connection::DatabasePool::Sqlite(pool) = db.pool() else {
            panic!("test database should use SQLite");
        };
        sqlx::query("DROP TABLE protocols")
            .execute(pool)
            .await
            .expect("test should remove the protocols table");

        let error = ScanComparator::new(db)
            .compare_protocols(1, 2)
            .await
            .expect_err("missing protocol table should fail the comparison");

        assert!(error.to_string().contains("Failed to fetch protocols"));
    }
}
