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
                    let fingerprint_sha256 = row.try_get("fingerprint_sha256").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field fingerprint_sha256: {}",
                            e
                        ))
                    })?;
                    let subject = row.try_get("subject").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field subject: {}",
                            e
                        ))
                    })?;
                    let issuer = row.try_get("issuer").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field issuer: {}",
                            e
                        ))
                    })?;
                    let not_before = row.try_get("not_before").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field not_before: {}",
                            e
                        ))
                    })?;
                    let not_after = row.try_get("not_after").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field not_after: {}",
                            e
                        ))
                    })?;
                    let is_ca = row.try_get("is_ca").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field is_ca: {}",
                            e
                        ))
                    })?;
                    let created_at = row.try_get("created_at").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field created_at: {}",
                            e
                        ))
                    })?;

                    let san_json: Option<String> = row.try_get("san_domains").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field san_domains: {}",
                            e
                        ))
                    })?;
                    let san_domains = CertificateRecord::parse_json_text_array(
                        san_json.as_deref(),
                        "san_domains",
                    )?;

                    let key_usage_json: Option<String> = row.try_get("key_usage").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field key_usage: {}",
                            e
                        ))
                    })?;
                    let key_usage = CertificateRecord::parse_json_text_array(
                        key_usage_json.as_deref(),
                        "key_usage",
                    )?;

                    let extended_key_usage_json: Option<String> =
                        row.try_get("extended_key_usage").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field extended_key_usage: {}",
                                e
                            ))
                        })?;
                    let extended_key_usage = CertificateRecord::parse_json_text_array(
                        extended_key_usage_json.as_deref(),
                        "extended_key_usage",
                    )?;

                    Ok(Some(CertificateRecord {
                        cert_id: row.try_get("cert_id").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field cert_id: {}",
                                e
                            ))
                        })?,
                        fingerprint_sha256,
                        subject,
                        issuer,
                        serial_number: row.try_get("serial_number").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field serial_number: {}",
                                e
                            ))
                        })?,
                        not_before,
                        not_after,
                        signature_algorithm: row.try_get("signature_algorithm").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field signature_algorithm: {}",
                                e
                            ))
                        })?,
                        public_key_algorithm: row.try_get("public_key_algorithm").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field public_key_algorithm: {}",
                                e
                            ))
                        })?,
                        public_key_size: row.try_get("public_key_size").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field public_key_size: {}",
                                e
                            ))
                        })?,
                        san_domains,
                        is_ca,
                        key_usage,
                        extended_key_usage,
                        der_bytes: row.try_get("der_bytes").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field der_bytes: {}",
                                e
                            ))
                        })?,
                        created_at,
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BindValue;
    use crate::db::analytics::test_support::{insert_scan, setup_db};
    use chrono::{TimeZone, Utc};
    use std::sync::Arc;

    async fn insert_certificate(
        db: &crate::db::CipherRunDatabase,
        scan_id: i64,
        fingerprint: &str,
    ) {
        let mut qb = db.pool().query_builder();
        let query = qb.insert_returning_query(
            "certificates",
            &[
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
            ],
            "cert_id",
        );
        let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let cert_id = db
            .pool()
            .execute_insert_returning(
                &query,
                vec![
                    BindValue::String(fingerprint.to_string()),
                    BindValue::String(format!("CN={fingerprint}")),
                    BindValue::String(format!("CN={fingerprint}")),
                    BindValue::OptString(None),
                    BindValue::DateTime(now),
                    BindValue::DateTime(now),
                    BindValue::OptString(None),
                    BindValue::OptString(None),
                    BindValue::OptInt32(Some(2048)),
                    BindValue::OptString(Some("[]".to_string())),
                    BindValue::Bool(false),
                    BindValue::OptString(Some("[]".to_string())),
                    BindValue::OptString(Some("[]".to_string())),
                    BindValue::OptBytes(None),
                ],
            )
            .await
            .expect("insert certificate");

        let mut qb = db.pool().query_builder();
        let query = qb.insert_query(
            "scan_certificates",
            &["scan_id", "cert_id", "chain_position"],
        );
        db.pool()
            .execute(
                &query,
                vec![
                    BindValue::Int64(scan_id),
                    BindValue::Int64(cert_id),
                    BindValue::Int32(0),
                ],
            )
            .await
            .expect("link leaf certificate");
    }

    #[tokio::test]
    async fn compares_leaf_certificate_fields_and_missing_certificates() {
        let db = setup_db("scan-comparator-certificates").await;
        let first = insert_scan(&db, "example.test", 443, Utc::now(), None, None).await;
        let second = insert_scan(&db, "example.test", 443, Utc::now(), None, None).await;
        insert_certificate(&db, first, "first").await;
        insert_certificate(&db, second, "second").await;

        let diff = ScanComparator::new(db.clone())
            .compare_certificates(first, second)
            .await
            .expect("compare certificates");
        assert!(diff.fingerprint_changed);
        assert!(diff.subject_changed);
        assert!(diff.issuer_changed);
        assert!(!diff.key_size_changed);
        assert!(!diff.expiry_changed);
        assert_eq!(diff.scan_1_cert.unwrap().fingerprint, "first");
        assert_eq!(diff.scan_2_cert.unwrap().fingerprint, "second");

        let without_cert = insert_scan(&db, "example.test", 443, Utc::now(), None, None).await;
        let missing = ScanComparator::new(db.clone())
            .compare_certificates(without_cert, first)
            .await
            .expect("compare missing certificate");
        assert!(missing.fingerprint_changed);
        assert!(missing.scan_1_cert.is_none());
        assert!(missing.scan_2_cert.is_some());

        let both_missing = ScanComparator::new(db)
            .compare_certificates(without_cert, without_cert)
            .await
            .expect("compare two missing certificates");
        assert!(!both_missing.fingerprint_changed);
    }

    #[tokio::test]
    async fn sqlite_comparison_maps_invalid_certificate_field_types() {
        let db = setup_db("scan-comparator-invalid-certificate-field").await;
        let DatabasePool::Sqlite(pool) = db.pool() else {
            panic!("test database should use SQLite");
        };
        for (index, (field, invalid_value)) in [
            ("fingerprint_sha256", "X'00'"),
            ("subject", "X'00'"),
            ("issuer", "X'00'"),
            ("not_before", "X'00'"),
            ("not_after", "X'00'"),
            ("is_ca", "X'00'"),
            ("created_at", "X'00'"),
            ("san_domains", "X'00'"),
            ("key_usage", "X'00'"),
            ("extended_key_usage", "X'00'"),
            ("serial_number", "X'00'"),
            ("signature_algorithm", "X'00'"),
            ("public_key_algorithm", "X'00'"),
            ("public_key_size", "X'00'"),
        ]
        .into_iter()
        .enumerate()
        {
            let scan_id = insert_scan(&db, "example.test", 443, Utc::now(), None, None).await;
            let fingerprint = format!("invalid-{field}-{index}");
            insert_certificate(&db, scan_id, &fingerprint).await;
            sqlx::query(&format!(
                "UPDATE certificates SET {field} = {invalid_value} WHERE fingerprint_sha256 = ?"
            ))
            .bind(&fingerprint)
            .execute(pool)
            .await
            .expect("test should store an invalid SQLite value");

            let error = ScanComparator::new(db.clone())
                .compare_certificates(scan_id, scan_id)
                .await
                .expect_err("invalid certificate field type should be rejected");
            assert!(
                error
                    .to_string()
                    .contains(&format!("Invalid certificate field {field}")),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[cfg(feature = "db-postgres")]
    #[tokio::test]
    async fn postgres_comparison_reads_leaf_certificates_and_maps_query_errors() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Ok(url) = std::env::var("CIPHERRUN_TEST_POSTGRES_URL") else {
            return;
        };
        let admin = PgPoolOptions::new()
            .connect_with(PgConnectOptions::from_str(&url).expect("test URL should be valid"))
            .await
            .expect("test PostgreSQL should accept connections");
        let schema = format!("cipherrun_test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("test schema should be created");

        let options = PgConnectOptions::from_str(&url)
            .expect("test URL should be valid")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .connect_with(options)
            .await
            .expect("test PostgreSQL schema should accept connections");
        sqlx::query(
            "CREATE TABLE certificates (\
                cert_id BIGSERIAL PRIMARY KEY, fingerprint_sha256 TEXT NOT NULL, \
                subject TEXT NOT NULL, issuer TEXT NOT NULL, serial_number TEXT, \
                not_before TIMESTAMPTZ NOT NULL, not_after TIMESTAMPTZ NOT NULL, \
                signature_algorithm TEXT, public_key_algorithm TEXT, public_key_size INTEGER, \
                san_domains TEXT[] NOT NULL DEFAULT '{}', is_ca BOOLEAN NOT NULL, \
                key_usage TEXT[] NOT NULL DEFAULT '{}', \
                extended_key_usage TEXT[] NOT NULL DEFAULT '{}', der_bytes BYTEA, \
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP\
            )",
        )
        .execute(&pool)
        .await
        .expect("test certificates table should be created");
        sqlx::query(
            "CREATE TABLE scan_certificates (\
                scan_id BIGINT NOT NULL, cert_id BIGINT NOT NULL, chain_position INTEGER NOT NULL\
            )",
        )
        .execute(&pool)
        .await
        .expect("test scan-certificate table should be created");

        let now = Utc::now();
        for (scan_id, fingerprint, subject, issuer, key_size, not_after) in [
            (1_i64, "first", "CN=first", "CN=CA A", 2048_i32, now),
            (
                2_i64,
                "second",
                "CN=second",
                "CN=CA B",
                4096_i32,
                now + chrono::Duration::days(1),
            ),
        ] {
            let certificate_id: i64 = sqlx::query_scalar(
                "INSERT INTO certificates (fingerprint_sha256, subject, issuer, not_before, \
                    not_after, public_key_size, san_domains, is_ca, key_usage, \
                    extended_key_usage) VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8, $9) \
                    RETURNING cert_id",
            )
            .bind(fingerprint)
            .bind(subject)
            .bind(issuer)
            .bind(now)
            .bind(not_after)
            .bind(key_size)
            .bind(vec!["example.test".to_string()])
            .bind(vec!["digitalSignature".to_string()])
            .bind(vec!["serverAuth".to_string()])
            .fetch_one(&pool)
            .await
            .expect("test certificate should be inserted");
            sqlx::query(
                "INSERT INTO scan_certificates (scan_id, cert_id, chain_position) \
                    VALUES ($1, $2, 0)",
            )
            .bind(scan_id)
            .bind(certificate_id)
            .execute(&pool)
            .await
            .expect("leaf certificate should be linked to its scan");
        }

        let database = Arc::new(crate::db::CipherRunDatabase::from_pool(
            DatabasePool::Postgres(pool.clone()),
        ));
        let comparator = ScanComparator::new(database);
        let diff = comparator
            .compare_certificates(1, 2)
            .await
            .expect("PostgreSQL leaf certificates should compare");
        assert!(diff.fingerprint_changed);
        assert!(diff.subject_changed);
        assert!(diff.issuer_changed);
        assert!(diff.key_size_changed);
        assert!(diff.expiry_changed);
        assert_eq!(diff.scan_1_cert.unwrap().fingerprint, "first");
        assert_eq!(diff.scan_2_cert.unwrap().fingerprint, "second");

        let missing = comparator
            .compare_certificates(1, 99)
            .await
            .expect("missing leaf certificate should compare");
        assert!(missing.fingerprint_changed);
        assert!(missing.scan_1_cert.is_some());
        assert!(missing.scan_2_cert.is_none());
        let both_missing = comparator
            .compare_certificates(98, 99)
            .await
            .expect("two missing leaf certificates should compare");
        assert!(!both_missing.fingerprint_changed);

        sqlx::query("DROP TABLE certificates CASCADE")
            .execute(&pool)
            .await
            .expect("test should remove the certificates table");
        assert!(
            comparator
                .compare_certificates(1, 2)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch certificate")
        );

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("test schema should be removed");
        admin.close().await;
    }
}
