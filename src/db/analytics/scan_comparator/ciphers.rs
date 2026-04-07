// Cipher comparison methods for ScanComparator

use super::{CipherDiff, CipherInfo, ScanComparator};
use crate::db::connection::DatabasePool;
use crate::db::CipherRecord;
use std::collections::HashMap;

impl ScanComparator {
    pub(crate) async fn compare_ciphers(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<CipherDiff> {
        let ciphers1 = self.get_ciphers(scan_id_1).await?;
        let ciphers2 = self.get_ciphers(scan_id_2).await?;

        // Use string references as HashMap keys to avoid cloning
        let set1: HashMap<&str, &CipherRecord> = ciphers1
            .iter()
            .map(|c| (c.cipher_name.as_str(), c))
            .collect();
        let set2: HashMap<&str, &CipherRecord> = ciphers2
            .iter()
            .map(|c| (c.cipher_name.as_str(), c))
            .collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut unchanged = Vec::new();

        // Helper function to convert CipherRecord to CipherInfo (reduces duplication)
        let to_cipher_info = |cipher: &CipherRecord| CipherInfo {
            name: cipher.cipher_name.clone(), // Necessary: building owned result
            protocol: cipher.protocol_name.clone(),
            strength: cipher.strength.clone(),
            forward_secrecy: cipher.forward_secrecy,
        };

        for (name, cipher) in &set2 {
            if !set1.contains_key(name) {
                added.push(to_cipher_info(cipher));
            } else {
                unchanged.push(to_cipher_info(cipher));
            }
        }

        for (name, cipher) in &set1 {
            if !set2.contains_key(name) {
                removed.push(to_cipher_info(cipher));
            }
        }

        Ok(CipherDiff {
            added,
            removed,
            unchanged,
        })
    }

    async fn get_ciphers(&self, scan_id: i64) -> crate::Result<Vec<CipherRecord>> {
        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let ciphers = sqlx::query_as::<_, CipherRecord>(
                    "SELECT cipher_id, scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength FROM cipher_suites WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ciphers: {}", e)))?;
                Ok(ciphers)
            }
            DatabasePool::Sqlite(pool) => {
                let ciphers = sqlx::query_as::<_, CipherRecord>(
                    "SELECT cipher_id, scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength FROM cipher_suites WHERE scan_id = ?"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ciphers: {}", e)))?;
                Ok(ciphers)
            }
        }
    }
}
