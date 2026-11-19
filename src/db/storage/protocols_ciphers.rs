use crate::application::PersistedScan;
use crate::db::models::ProtocolRecord;
use crate::db::{BindValue, CipherRunDatabase};

impl CipherRunDatabase {
    pub(crate) async fn store_protocols(
        &self,
        scan_id: i64,
        results: &PersistedScan,
    ) -> crate::Result<()> {
        if results.protocols.is_empty() {
            return Ok(());
        }

        let mut qb = self.pool.query_builder();
        let columns = &["scan_id", "protocol_name", "enabled", "preferred"];

        let mut all_bindings = Vec::new();
        for protocol_result in &results.protocols {
            let protocol = ProtocolRecord::new(
                scan_id,
                protocol_result.protocol_name.clone(),
                protocol_result.enabled,
                protocol_result.preferred,
            );

            all_bindings.push(vec![
                BindValue::Int64(protocol.scan_id),
                BindValue::String(protocol.protocol_name),
                BindValue::Bool(protocol.enabled),
                BindValue::Bool(protocol.preferred),
            ]);
        }

        let query = qb.batch_insert_query("protocols", columns, all_bindings.len());
        let flat_bindings: Vec<BindValue> = all_bindings.into_iter().flatten().collect();

        self.pool
            .execute(&query, flat_bindings)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to batch insert protocols: {}", e))
            })?;

        Ok(())
    }

    pub(crate) async fn store_ciphers(
        &self,
        scan_id: i64,
        results: &PersistedScan,
    ) -> crate::Result<()> {
        let total_ciphers = results.ciphers.len();

        if total_ciphers == 0 {
            return Ok(());
        }

        let columns = &[
            "scan_id",
            "protocol_name",
            "cipher_name",
            "key_exchange",
            "authentication",
            "encryption",
            "mac",
            "bits",
            "forward_secrecy",
            "strength",
        ];

        let mut all_bindings = Vec::with_capacity(total_ciphers);

        for cipher_result in &results.ciphers {
            all_bindings.push(vec![
                BindValue::Int64(scan_id),
                BindValue::String(cipher_result.protocol_name.clone()),
                BindValue::String(cipher_result.cipher_name.clone()),
                BindValue::OptString(cipher_result.key_exchange.clone()),
                BindValue::OptString(cipher_result.authentication.clone()),
                BindValue::OptString(cipher_result.encryption.clone()),
                BindValue::OptString(cipher_result.mac.clone()),
                BindValue::OptInt32(cipher_result.bits),
                BindValue::Bool(cipher_result.forward_secrecy),
                BindValue::String(cipher_result.strength.clone()),
            ]);
        }

        let mut qb = self.pool.query_builder();
        let query = qb.batch_insert_query("cipher_suites", columns, all_bindings.len());
        let flat_bindings: Vec<BindValue> = all_bindings.into_iter().flatten().collect();

        self.pool
            .execute(&query, flat_bindings)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to batch insert ciphers: {}", e))
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::persistence::{PersistedCipher, PersistedProtocol};
    use crate::db::DatabaseConfig;
    use std::path::PathBuf;

    fn persisted_scan(
        protocols: Vec<PersistedProtocol>,
        ciphers: Vec<PersistedCipher>,
    ) -> PersistedScan {
        PersistedScan {
            target_hostname: "example.com".to_string(),
            target_port: 443,
            principal_id: None,
            tenant_id: None,
            created_by_key_id: None,
            overall_grade: None,
            overall_score: None,
            scan_duration_ms: 0,
            revocation: None,
            protocols,
            ciphers,
            vulnerabilities: Vec::new(),
            ratings: Vec::new(),
            certificates: Vec::new(),
        }
    }

    async fn test_database() -> CipherRunDatabase {
        CipherRunDatabase::new(&DatabaseConfig::sqlite(PathBuf::from(":memory:")))
            .await
            .expect("SQLite test database should initialize")
    }

    #[tokio::test]
    async fn stores_protocol_and_cipher_rows_with_optional_values() {
        let database = test_database().await;
        let scan_id = database
            .store_scan(&persisted_scan(Vec::new(), Vec::new()))
            .await
            .expect("empty scan should create a parent row");
        let results = persisted_scan(
            vec![
                PersistedProtocol {
                    protocol_name: "TLS 1.3".to_string(),
                    enabled: true,
                    preferred: true,
                },
                PersistedProtocol {
                    protocol_name: "TLS 1.0".to_string(),
                    enabled: false,
                    preferred: false,
                },
            ],
            vec![
                PersistedCipher {
                    protocol_name: "TLS 1.3".to_string(),
                    cipher_name: "TLS_AES_128_GCM_SHA256".to_string(),
                    key_exchange: Some("ECDHE".to_string()),
                    authentication: Some("RSA".to_string()),
                    encryption: Some("AESGCM".to_string()),
                    mac: Some("AEAD".to_string()),
                    bits: Some(128),
                    forward_secrecy: true,
                    strength: "high".to_string(),
                },
                PersistedCipher {
                    protocol_name: "TLS 1.0".to_string(),
                    cipher_name: "TLS_RSA_WITH_NULL_MD5".to_string(),
                    key_exchange: None,
                    authentication: None,
                    encryption: None,
                    mac: None,
                    bits: None,
                    forward_secrecy: false,
                    strength: "null".to_string(),
                },
            ],
        );

        database
            .store_protocols(scan_id, &results)
            .await
            .expect("protocol batch should persist");
        database
            .store_ciphers(scan_id, &results)
            .await
            .expect("cipher batch should persist");

        let protocol_count = database
            .pool()
            .fetch_optional_id(
                "SELECT COUNT(*) FROM protocols WHERE scan_id = $1 AND protocol_name = $2 AND enabled = $3 AND preferred = $4",
                vec![
                    BindValue::Int64(scan_id),
                    BindValue::String("TLS 1.3".to_string()),
                    BindValue::Bool(true),
                    BindValue::Bool(true),
                ],
            )
            .await
            .expect("protocol row should be readable");
        assert_eq!(protocol_count, Some(1));

        let cipher_count = database
            .pool()
            .fetch_optional_id(
                "SELECT COUNT(*) FROM cipher_suites WHERE scan_id = $1 AND protocol_name = $2 AND cipher_name = $3 AND key_exchange = $4 AND authentication = $5 AND encryption = $6 AND mac = $7 AND bits = $8 AND forward_secrecy = $9 AND strength = $10",
                vec![
                    BindValue::Int64(scan_id),
                    BindValue::String("TLS 1.3".to_string()),
                    BindValue::String("TLS_AES_128_GCM_SHA256".to_string()),
                    BindValue::OptString(Some("ECDHE".to_string())),
                    BindValue::OptString(Some("RSA".to_string())),
                    BindValue::OptString(Some("AESGCM".to_string())),
                    BindValue::OptString(Some("AEAD".to_string())),
                    BindValue::OptInt32(Some(128)),
                    BindValue::Bool(true),
                    BindValue::String("high".to_string()),
                ],
            )
            .await
            .expect("cipher row should be readable");
        assert_eq!(cipher_count, Some(1));

        let null_cipher_count = database
            .pool()
            .fetch_optional_id(
                "SELECT COUNT(*) FROM cipher_suites WHERE scan_id = $1 AND protocol_name = $2 AND cipher_name = $3 AND key_exchange IS NULL AND authentication IS NULL AND encryption IS NULL AND mac IS NULL AND bits IS NULL AND forward_secrecy = $4 AND strength = $5",
                vec![
                    BindValue::Int64(scan_id),
                    BindValue::String("TLS 1.0".to_string()),
                    BindValue::String("TLS_RSA_WITH_NULL_MD5".to_string()),
                    BindValue::Bool(false),
                    BindValue::String("null".to_string()),
                ],
            )
            .await
            .expect("nullable cipher row should be readable");
        assert_eq!(null_cipher_count, Some(1));

        database.close().await;
    }

    #[tokio::test]
    async fn store_errors_include_the_failed_table_operation() {
        let database = test_database().await;
        let protocols = persisted_scan(
            vec![PersistedProtocol {
                protocol_name: "TLS 1.3".to_string(),
                enabled: true,
                preferred: false,
            }],
            Vec::new(),
        );
        database
            .pool()
            .execute("DROP TABLE protocols", Vec::new())
            .await
            .expect("protocol table should drop");
        let error = database
            .store_protocols(1, &protocols)
            .await
            .expect_err("missing protocol table should fail");
        assert!(
            error
                .to_string()
                .contains("Failed to batch insert protocols")
        );

        let ciphers = persisted_scan(
            Vec::new(),
            vec![PersistedCipher {
                protocol_name: "TLS 1.3".to_string(),
                cipher_name: "TLS_AES_128_GCM_SHA256".to_string(),
                key_exchange: None,
                authentication: None,
                encryption: None,
                mac: None,
                bits: None,
                forward_secrecy: false,
                strength: "high".to_string(),
            }],
        );
        database
            .pool()
            .execute("DROP TABLE cipher_suites", Vec::new())
            .await
            .expect("cipher table should drop");
        let error = database
            .store_ciphers(1, &ciphers)
            .await
            .expect_err("missing cipher table should fail");
        assert!(error.to_string().contains("Failed to batch insert ciphers"));

        database.close().await;
    }
}
