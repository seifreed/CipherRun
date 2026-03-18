use crate::application::PersistedScan;
use crate::db::{BindValue, CipherRunDatabase};

impl CipherRunDatabase {
    pub(crate) async fn store_vulnerabilities(
        &self,
        scan_id: i64,
        results: &PersistedScan,
    ) -> crate::Result<()> {
        let mut qb = self.pool.query_builder();
        let query = qb.insert_query(
            "vulnerabilities",
            &[
                "scan_id",
                "vulnerability_type",
                "severity",
                "description",
                "cve_id",
                "affected_component",
            ],
        );

        for vuln_result in &results.vulnerabilities {
            self.pool
                .execute(
                    &query,
                    vec![
                        BindValue::Int64(scan_id),
                        BindValue::String(vuln_result.vulnerability_type.clone()),
                        BindValue::String(vuln_result.severity.clone()),
                        BindValue::OptString(vuln_result.description.clone()),
                        BindValue::OptString(vuln_result.cve_id.clone()),
                        BindValue::OptString(None),
                    ],
                )
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to insert vulnerability: {}", e))
                })?;
        }

        Ok(())
    }

    pub(crate) async fn store_ratings(
        &self,
        scan_id: i64,
        results: &PersistedScan,
    ) -> crate::Result<()> {
        let mut qb = self.pool.query_builder();
        let query = qb.insert_query(
            "ratings",
            &["scan_id", "category", "score", "grade", "rationale"],
        );

        for rating_record in &results.ratings {
            self.pool
                .execute(
                    &query,
                    vec![
                        BindValue::Int64(scan_id),
                        BindValue::String(rating_record.category.clone()),
                        BindValue::Int32(rating_record.score),
                        BindValue::OptString(rating_record.grade.clone()),
                        BindValue::OptString(rating_record.rationale.clone()),
                    ],
                )
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to insert rating: {}", e))
                })?;
        }

        Ok(())
    }
}
