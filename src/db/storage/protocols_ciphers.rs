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
