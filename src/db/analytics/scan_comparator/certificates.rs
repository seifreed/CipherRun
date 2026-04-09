// Certificate comparison methods for ScanComparator

use super::{CertSummary, CertificateDiff, ScanComparator};
use crate::db::CertificateRecord;
use crate::db::connection::DatabasePool;

impl ScanComparator {
    pub(crate) async fn compare_certificates(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<CertificateDiff> {
        let cert1 = self.get_leaf_certificate(scan_id_1).await?;
        let cert2 = self.get_leaf_certificate(scan_id_2).await?;

        let fingerprint_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.fingerprint_sha256 != c2.fingerprint_sha256,
            (None, Some(_)) | (Some(_), None) => true,
            (None, None) => false,
        };

        let subject_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.subject != c2.subject,
            _ => false,
        };

        let issuer_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.issuer != c2.issuer,
            _ => false,
        };

        let key_size_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.public_key_size != c2.public_key_size,
            _ => false,
        };

        let expiry_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.not_after != c2.not_after,
            _ => false,
        };

        let scan_1_cert = cert1.map(|c| CertSummary {
            subject: c.subject,
            issuer: c.issuer,
            not_before: c.not_before,
            not_after: c.not_after,
            key_size: c.public_key_size,
            fingerprint: c.fingerprint_sha256,
        });

        let scan_2_cert = cert2.map(|c| CertSummary {
            subject: c.subject,
            issuer: c.issuer,
            not_before: c.not_before,
            not_after: c.not_after,
            key_size: c.public_key_size,
            fingerprint: c.fingerprint_sha256,
        });

        Ok(CertificateDiff {
            fingerprint_changed,
            subject_changed,
            issuer_changed,
            key_size_changed,
            expiry_changed,
            scan_1_cert,
            scan_2_cert,
        })
    }

    async fn get_leaf_certificate(&self, scan_id: i64) -> crate::Result<Option<CertificateRecord>> {
        use sqlx::Row;

        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let cert = sqlx::query_as::<_, CertificateRecord>(
                    r#"
                    SELECT c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.serial_number,
                           c.not_before, c.not_after, c.signature_algorithm, c.public_key_algorithm,
                           c.public_key_size, c.san_domains, c.is_ca, c.key_usage, c.extended_key_usage,
                           c.der_bytes, c.created_at
                    FROM certificates c
                    JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                    WHERE sc.scan_id = $1 AND sc.chain_position = 0
                    "#
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e)))?;
                Ok(cert)
            }
            DatabasePool::Sqlite(pool) => {
                let row = sqlx::query(
                    r#"
                    SELECT c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.serial_number,
                           c.not_before, c.not_after, c.signature_algorithm, c.public_key_algorithm,
                           c.public_key_size, c.san_domains, c.is_ca, c.key_usage, c.extended_key_usage,
                           c.der_bytes, c.created_at
                    FROM certificates c
                    JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                    WHERE sc.scan_id = ? AND sc.chain_position = 0
                    "#
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e)))?;

                if let Some(row) = row {
                    let san_json: Option<String> = row.try_get("san_domains").ok();
                    let san_domains = CertificateRecord::parse_json_text_array(
                        san_json.as_deref(),
                        "san_domains",
                    )?;

                    let key_usage_json: Option<String> = row.try_get("key_usage").ok();
                    let key_usage = CertificateRecord::parse_json_text_array(
                        key_usage_json.as_deref(),
                        "key_usage",
                    )?;

                    let extended_key_usage_json: Option<String> =
                        row.try_get("extended_key_usage").ok();
                    let extended_key_usage = CertificateRecord::parse_json_text_array(
                        extended_key_usage_json.as_deref(),
                        "extended_key_usage",
                    )?;

                    Ok(Some(CertificateRecord {
                        cert_id: row.try_get("cert_id").ok(),
                        fingerprint_sha256: row.try_get("fingerprint_sha256").unwrap_or_default(),
                        subject: row.try_get("subject").unwrap_or_default(),
                        issuer: row.try_get("issuer").unwrap_or_default(),
                        serial_number: row.try_get("serial_number").ok(),
                        not_before: row
                            .try_get("not_before")
                            .unwrap_or_else(|_| chrono::Utc::now()),
                        not_after: row
                            .try_get("not_after")
                            .unwrap_or_else(|_| chrono::Utc::now()),
                        signature_algorithm: row.try_get("signature_algorithm").ok(),
                        public_key_algorithm: row.try_get("public_key_algorithm").ok(),
                        public_key_size: row.try_get("public_key_size").ok(),
                        san_domains,
                        is_ca: row.try_get("is_ca").unwrap_or(false),
                        key_usage,
                        extended_key_usage,
                        der_bytes: row.try_get("der_bytes").ok(),
                        created_at: row
                            .try_get("created_at")
                            .unwrap_or_else(|_| chrono::Utc::now()),
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }
}
