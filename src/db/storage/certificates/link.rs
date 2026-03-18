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
