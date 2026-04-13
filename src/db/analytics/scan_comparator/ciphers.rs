// Cipher comparison methods for ScanComparator

use super::{CipherChangeInfo, CipherDetailInfo, CipherDiff, CipherInfo, ScanComparator};
use crate::db::CipherRecord;
use crate::db::connection::DatabasePool;
use std::collections::BTreeMap;

fn sort_cipher_infos(ciphers: &mut [CipherInfo]) {
    ciphers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.strength.cmp(&b.strength))
            .then_with(|| a.forward_secrecy.cmp(&b.forward_secrecy))
    });
}

fn sort_cipher_changes(changes: &mut [CipherChangeInfo]) {
    changes.sort_by(|a, b| {
        a.current
            .protocol
            .cmp(&b.current.protocol)
            .then_with(|| a.current.name.cmp(&b.current.name))
            .then_with(|| a.changed_fields.cmp(&b.changed_fields))
            .then_with(|| a.previous.strength.cmp(&b.previous.strength))
            .then_with(|| a.current.strength.cmp(&b.current.strength))
    });
}

impl ScanComparator {
    pub(crate) async fn compare_ciphers(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<CipherDiff> {
        let ciphers1 = self.get_ciphers(scan_id_1).await?;
        let ciphers2 = self.get_ciphers(scan_id_2).await?;

        Ok(compare_cipher_records(&ciphers1, &ciphers2))
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

fn cipher_identity(cipher: &CipherRecord) -> (String, String) {
    (cipher.protocol_name.clone(), cipher.cipher_name.clone())
}

fn to_cipher_info(cipher: &CipherRecord) -> CipherInfo {
    CipherInfo {
        name: cipher.cipher_name.clone(),
        protocol: cipher.protocol_name.clone(),
        strength: cipher.strength.clone(),
        forward_secrecy: cipher.forward_secrecy,
    }
}

fn to_cipher_detail_info(cipher: &CipherRecord) -> CipherDetailInfo {
    CipherDetailInfo {
        name: cipher.cipher_name.clone(),
        protocol: cipher.protocol_name.clone(),
        key_exchange: cipher.key_exchange.clone(),
        authentication: cipher.authentication.clone(),
        encryption: cipher.encryption.clone(),
        mac: cipher.mac.clone(),
        bits: cipher.bits,
        forward_secrecy: cipher.forward_secrecy,
        strength: cipher.strength.clone(),
    }
}

fn to_cipher_change_info(previous: &CipherRecord, current: &CipherRecord) -> CipherChangeInfo {
    CipherChangeInfo {
        previous: to_cipher_detail_info(previous),
        current: to_cipher_detail_info(current),
        changed_fields: previous
            .changed_fields(current)
            .into_iter()
            .map(|field| field.to_string())
            .collect(),
    }
}

fn compare_cipher_records(ciphers1: &[CipherRecord], ciphers2: &[CipherRecord]) -> CipherDiff {
    let set1: BTreeMap<(String, String), &CipherRecord> = ciphers1
        .iter()
        .map(|cipher| (cipher_identity(cipher), cipher))
        .collect();
    let set2: BTreeMap<(String, String), &CipherRecord> = ciphers2
        .iter()
        .map(|cipher| (cipher_identity(cipher), cipher))
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = Vec::new();
    let mut changed = Vec::new();

    for (identity, cipher) in &set2 {
        if let Some(previous) = set1.get(identity) {
            if previous.same_attributes(cipher) {
                unchanged.push(to_cipher_info(cipher));
            } else {
                changed.push(to_cipher_change_info(previous, cipher));
            }
        } else {
            added.push(to_cipher_info(cipher));
        }
    }

    for (identity, cipher) in &set1 {
        if !set2.contains_key(identity) {
            removed.push(to_cipher_info(cipher));
        }
    }

    sort_cipher_infos(&mut added);
    sort_cipher_infos(&mut removed);
    sort_cipher_infos(&mut unchanged);
    sort_cipher_changes(&mut changed);

    CipherDiff {
        added,
        removed,
        unchanged,
        changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cipher_record(protocol: &str, name: &str, strength: &str) -> CipherRecord {
        CipherRecord::new(
            1,
            protocol.to_string(),
            name.to_string(),
            strength.to_string(),
            true,
        )
    }

    #[test]
    fn test_compare_cipher_records_distinguishes_protocol_identity() {
        let scan1 = vec![make_cipher_record(
            "TLS 1.2",
            "TLS_AES_128_GCM_SHA256",
            "strong",
        )];
        let scan2 = vec![make_cipher_record(
            "TLS 1.3",
            "TLS_AES_128_GCM_SHA256",
            "strong",
        )];

        let diff = compare_cipher_records(&scan1, &scan2);

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.unchanged.is_empty());
        assert!(diff.changed.is_empty());
        assert_eq!(diff.added[0].protocol, "TLS 1.3");
        assert_eq!(diff.removed[0].protocol, "TLS 1.2");
    }

    #[test]
    fn test_compare_cipher_records_marks_attribute_changes() {
        let scan1 = vec![
            CipherRecord::new(
                1,
                "TLS 1.2".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "strong".to_string(),
                true,
            )
            .with_details(
                "ECDHE".to_string(),
                "RSA".to_string(),
                "AES_128_GCM".to_string(),
                "AEAD".to_string(),
                128,
            ),
        ];
        let scan2 = vec![
            CipherRecord::new(
                2,
                "TLS 1.2".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "weak".to_string(),
                false,
            )
            .with_details(
                "RSA".to_string(),
                "ECDSA".to_string(),
                "AES_128_CBC".to_string(),
                "HMAC-SHA256".to_string(),
                112,
            ),
        ];

        let diff = compare_cipher_records(&scan1, &scan2);

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.unchanged.is_empty());
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].current.name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(
            diff.changed[0].changed_fields,
            vec![
                "key_exchange".to_string(),
                "authentication".to_string(),
                "encryption".to_string(),
                "mac".to_string(),
                "bits".to_string(),
                "forward_secrecy".to_string(),
                "strength".to_string(),
            ]
        );
    }
}
