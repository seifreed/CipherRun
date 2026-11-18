use crate::db::{BindValue, CipherRunDatabase};

impl CipherRunDatabase {
    fn build_scan_certificate_columns() -> [&'static str; 3] {
        ["scan_id", "cert_id", "chain_position"]
    }

    pub(crate) async fn link_certificate(
        &self,
        scan_id: i64,
        cert_id: i64,
        position: i32,
    ) -> crate::Result<()> {
        let mut qb = self.pool.query_builder();
        let query = qb.insert_query("scan_certificates", &Self::build_scan_certificate_columns());

        self.pool
            .execute(
                &query,
                Self::build_scan_certificate_bindings(scan_id, cert_id, position),
            )
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to link certificate: {}", e))
            })
    }

    fn build_scan_certificate_bindings(
        scan_id: i64,
        cert_id: i64,
        position: i32,
    ) -> Vec<BindValue> {
        vec![
            BindValue::Int64(scan_id),
            BindValue::Int64(cert_id),
            BindValue::Int32(position),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn link_certificate_preserves_database_failures() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config =
            crate::db::DatabaseConfig::sqlite(PathBuf::from(directory.path().join("test.db")));
        let database = CipherRunDatabase::new(&config)
            .await
            .expect("test database should initialize");

        let error = database
            .link_certificate(-1, -1, 0)
            .await
            .expect_err("missing scan and certificate IDs should violate foreign keys");

        assert!(matches!(error, crate::TlsError::DatabaseError(_)));
    }
}
