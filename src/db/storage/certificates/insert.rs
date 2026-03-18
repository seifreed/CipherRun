use crate::db::{BindValue, CipherRunDatabase};

impl CipherRunDatabase {
    fn serialize_certificate_list(values: &[String]) -> String {
        serde_json::to_string(values).unwrap_or_default()
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

    fn build_certificate_insert_bindings(
        fingerprint: &str,
        subject: &str,
        issuer: &str,
        serial_number: Option<&str>,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
        signature_algorithm: Option<&str>,
        public_key_algorithm: Option<&str>,
        public_key_size: Option<i32>,
        san_domains: &[String],
        is_ca: bool,
        key_usage: &[String],
        extended_key_usage: &[String],
        der_bytes: Option<&[u8]>,
    ) -> Vec<BindValue> {
        let san_json = Self::serialize_certificate_list(san_domains);
        let key_usage_json = Self::serialize_certificate_list(key_usage);
        let extended_key_usage_json = Self::serialize_certificate_list(extended_key_usage);

        vec![
            BindValue::String(fingerprint.to_string()),
            BindValue::String(subject.to_string()),
            BindValue::String(issuer.to_string()),
            BindValue::OptString(serial_number.map(String::from)),
            BindValue::DateTime(not_before),
            BindValue::DateTime(not_after),
            BindValue::OptString(signature_algorithm.map(String::from)),
            BindValue::OptString(public_key_algorithm.map(String::from)),
            BindValue::OptInt32(public_key_size),
            BindValue::String(san_json),
            BindValue::Bool(is_ca),
            BindValue::String(key_usage_json),
            BindValue::String(extended_key_usage_json),
            BindValue::OptBytes(der_bytes.map(Vec::from)),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn insert_or_get_certificate_direct(
        &self,
        fingerprint: &str,
        subject: &str,
        issuer: &str,
        serial_number: Option<&str>,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
        signature_algorithm: Option<&str>,
        public_key_algorithm: Option<&str>,
        public_key_size: Option<i32>,
        san_domains: &[String],
        is_ca: bool,
        key_usage: &[String],
        extended_key_usage: &[String],
        der_bytes: Option<&[u8]>,
    ) -> crate::Result<i64> {
        if let Some(existing_id) = self.find_existing_certificate_id(fingerprint).await? {
            return Ok(existing_id);
        }

        self.insert_certificate_record(
            fingerprint,
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            signature_algorithm,
            public_key_algorithm,
            public_key_size,
            san_domains,
            is_ca,
            key_usage,
            extended_key_usage,
            der_bytes,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn insert_certificate_record(
        &self,
        fingerprint: &str,
        subject: &str,
        issuer: &str,
        serial_number: Option<&str>,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
        signature_algorithm: Option<&str>,
        public_key_algorithm: Option<&str>,
        public_key_size: Option<i32>,
        san_domains: &[String],
        is_ca: bool,
        key_usage: &[String],
        extended_key_usage: &[String],
        der_bytes: Option<&[u8]>,
    ) -> crate::Result<i64> {
        let mut qb = self.pool.query_builder();
        let insert_query = qb.insert_returning_query(
            "certificates",
            &Self::build_certificate_insert_columns(),
            "cert_id",
        );

        let bindings = Self::build_certificate_insert_bindings(
            fingerprint,
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            signature_algorithm,
            public_key_algorithm,
            public_key_size,
            san_domains,
            is_ca,
            key_usage,
            extended_key_usage,
            der_bytes,
        );

        self.pool
            .execute_insert_returning(&insert_query, bindings)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to insert certificate: {}", e))
            })
    }
}
