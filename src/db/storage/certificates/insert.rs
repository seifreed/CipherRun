use crate::db::{BindValue, CipherRunDatabase};

/// Grouped parameters for inserting a certificate into the database.
#[derive(Debug)]
pub(crate) struct CertificateInsertParams<'a> {
    pub fingerprint: &'a str,
    pub subject: &'a str,
    pub issuer: &'a str,
    pub serial_number: Option<&'a str>,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub signature_algorithm: Option<&'a str>,
    pub public_key_algorithm: Option<&'a str>,
    pub public_key_size: Option<i32>,
    pub san_domains: &'a [String],
    pub is_ca: bool,
    pub key_usage: &'a [String],
    pub extended_key_usage: &'a [String],
    pub der_bytes: Option<&'a [u8]>,
}

impl CipherRunDatabase {
    fn serialize_certificate_list(values: &[String]) -> String {
        serde_json::to_string(values).unwrap_or_else(|e| {
            tracing::error!("Failed to serialize certificate list: {}", e);
            "[]".to_string()
        })
    }

    fn build_certificate_insert_columns() -> [&'static str; 14] {
        [
            "fingerprint_sha256",
            "subject",
            "issuer",
            "serial_number",
            "not_before",
            "not_after",
            "signature_algorithm",
            "public_key_algorithm",
            "public_key_size",
            "san_domains",
            "is_ca",
            "key_usage",
            "extended_key_usage",
            "der_bytes",
        ]
    }

    fn build_certificate_insert_bindings(params: &CertificateInsertParams<'_>) -> Vec<BindValue> {
        let san_json = Self::serialize_certificate_list(params.san_domains);
        let key_usage_json = Self::serialize_certificate_list(params.key_usage);
        let extended_key_usage_json = Self::serialize_certificate_list(params.extended_key_usage);

        vec![
            BindValue::String(params.fingerprint.to_string()),
            BindValue::String(params.subject.to_string()),
            BindValue::String(params.issuer.to_string()),
            BindValue::OptString(params.serial_number.map(String::from)),
            BindValue::DateTime(params.not_before),
            BindValue::DateTime(params.not_after),
            BindValue::OptString(params.signature_algorithm.map(String::from)),
            BindValue::OptString(params.public_key_algorithm.map(String::from)),
            BindValue::OptInt32(params.public_key_size),
            BindValue::String(san_json),
            BindValue::Bool(params.is_ca),
            BindValue::String(key_usage_json),
            BindValue::String(extended_key_usage_json),
            BindValue::OptBytes(params.der_bytes.map(Vec::from)),
        ]
    }

    pub(crate) async fn insert_or_get_certificate_direct(
        &self,
        params: &CertificateInsertParams<'_>,
    ) -> crate::Result<i64> {
        // Fast path: check if certificate already exists
        if let Some(existing_id) = self
            .find_existing_certificate_id(params.fingerprint)
            .await?
        {
            return Ok(existing_id);
        }

        // Attempt insert using ON CONFLICT DO NOTHING to handle concurrent inserts
        // atomically instead of relying on error string matching.
        let mut qb = self.pool.query_builder();
        let upsert_query = qb.insert_on_conflict_do_nothing_query(
            "certificates",
            &Self::build_certificate_insert_columns(),
            "fingerprint_sha256",
            "cert_id",
        );

        let bindings = Self::build_certificate_insert_bindings(params);

        match self
            .pool
            .execute_insert_returning(&upsert_query, bindings)
            .await
        {
            Ok(id) => Ok(id),
            Err(_) => {
                // ON CONFLICT DO NOTHING returns no row when conflict occurs.
                // Look up the existing certificate that won the race.
                self.find_existing_certificate_id(params.fingerprint)
                    .await?
                    .ok_or_else(|| {
                        crate::TlsError::DatabaseError(format!(
                            "Certificate with fingerprint {} not found after conflict",
                            params.fingerprint
                        ))
                    })
            }
        }
    }
}
