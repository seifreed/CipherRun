use crate::db::{BindValue, CipherRunDatabase};

impl CipherRunDatabase {
    fn build_certificate_lookup_columns() -> (&'static str, &'static str, &'static str) {
        ("certificates", "cert_id", "fingerprint_sha256")
    }

    fn build_certificate_lookup_bindings(fingerprint: &str) -> Vec<BindValue> {
        vec![BindValue::String(fingerprint.to_string())]
    }

    pub(crate) async fn find_existing_certificate_id(
        &self,
        fingerprint: &str,
    ) -> crate::Result<Option<i64>> {
        let mut qb = self.pool.query_builder();
        let (table, id_column, where_column) = Self::build_certificate_lookup_columns();
        let select_query = qb.select_where_query(table, id_column, where_column);

        self.pool
            .fetch_optional_id(
                &select_query,
                Self::build_certificate_lookup_bindings(fingerprint),
            )
            .await
    }
}
