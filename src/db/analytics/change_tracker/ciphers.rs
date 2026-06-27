// ChangeTracker cipher-change detection and classification

use super::*;

impl ChangeTracker {
    pub(super) async fn detect_cipher_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let ciphers1 = self.get_ciphers(scan_id_1).await?;
        let ciphers2 = self.get_ciphers(scan_id_2).await?;

        let mut changes = Vec::new();

        let set1: BTreeMap<(String, String), &CipherRecord> = ciphers1
            .iter()
            .map(|cipher| (Self::cipher_identity(cipher), cipher))
            .collect();
        let set2: BTreeMap<(String, String), &CipherRecord> = ciphers2
            .iter()
            .map(|cipher| (Self::cipher_identity(cipher), cipher))
            .collect();

        let keys: BTreeSet<(String, String)> =
            set1.keys().cloned().chain(set2.keys().cloned()).collect();

        for key in keys {
            match (set1.get(&key), set2.get(&key)) {
                (Some(old), Some(new)) => {
                    if old.same_attributes(new) {
                        continue;
                    }

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Cipher,
                        severity: Self::cipher_change_severity(old, new),
                        description: format!(
                            "Cipher changed: {} [{}]",
                            old.cipher_name.as_str(),
                            old.protocol_name.as_str()
                        ),
                        previous_value: Some(Self::cipher_detail(old)),
                        current_value: Some(Self::cipher_detail(new)),
                        timestamp,
                    });
                }
                (Some(old), None) => {
                    let severity = if Self::is_weak_cipher_strength(&old.strength) {
                        ChangeSeverity::Low
                    } else {
                        ChangeSeverity::Info
                    };

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Cipher,
                        severity,
                        description: format!(
                            "Cipher removed: {} [{}]",
                            old.cipher_name.as_str(),
                            old.protocol_name.as_str()
                        ),
                        previous_value: Some(Self::cipher_detail(old)),
                        current_value: None,
                        timestamp,
                    });
                }
                (None, Some(new)) => {
                    let severity = match Self::cipher_strength_rank(&new.strength) {
                        0 => ChangeSeverity::High,
                        1 => ChangeSeverity::Medium,
                        _ => ChangeSeverity::Info,
                    };

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Cipher,
                        severity,
                        description: format!(
                            "Cipher added: {} [{}]",
                            new.cipher_name.as_str(),
                            new.protocol_name.as_str()
                        ),
                        previous_value: None,
                        current_value: Some(Self::cipher_detail(new)),
                        timestamp,
                    });
                }
                (None, None) => continue,
            }
        }

        Ok(changes)
    }

    fn cipher_identity(cipher: &CipherRecord) -> (String, String) {
        (
            protocol_identity(&cipher.protocol_name),
            cipher.cipher_name.clone(),
        )
    }

    fn is_weak_cipher_strength(strength: &str) -> bool {
        matches!(
            strength.to_ascii_lowercase().as_str(),
            "weak" | "low" | "export" | "null"
        )
    }

    fn cipher_strength_rank(strength: &str) -> i32 {
        match strength.to_ascii_lowercase().as_str() {
            "weak" | "low" | "export" | "null" => 0,
            "medium" => 1,
            "strong" | "high" => 2,
            _ => 1,
        }
    }

    fn cipher_change_severity(old: &CipherRecord, new: &CipherRecord) -> ChangeSeverity {
        let mut severity = ChangeSeverity::Info;

        if old.strength != new.strength {
            let strength_severity = match (
                Self::cipher_strength_rank(&old.strength),
                Self::cipher_strength_rank(&new.strength),
            ) {
                (old_rank, new_rank) if new_rank < old_rank => ChangeSeverity::High,
                (old_rank, new_rank) if new_rank > old_rank => ChangeSeverity::Low,
                _ => ChangeSeverity::Medium,
            };
            severity = severity.max(strength_severity);
        }

        if old.bits != new.bits {
            let bit_severity = match (old.bits, new.bits) {
                (Some(old_bits), Some(new_bits)) if new_bits < old_bits => ChangeSeverity::High,
                (Some(old_bits), Some(new_bits)) if new_bits > old_bits => ChangeSeverity::Low,
                _ => ChangeSeverity::Medium,
            };
            severity = severity.max(bit_severity);
        }

        if old.forward_secrecy != new.forward_secrecy {
            let fs_severity = if old.forward_secrecy && !new.forward_secrecy {
                ChangeSeverity::High
            } else {
                ChangeSeverity::Low
            };
            severity = severity.max(fs_severity);
        }

        if old.key_exchange != new.key_exchange
            || old.authentication != new.authentication
            || old.encryption != new.encryption
            || old.mac != new.mac
        {
            severity = severity.max(ChangeSeverity::Medium);
        }

        severity
    }

    fn cipher_detail(cipher: &CipherRecord) -> String {
        format!(
            "protocol={}, cipher={}, key_exchange={}, authentication={}, encryption={}, mac={}, bits={}, forward_secrecy={}, strength={}",
            cipher.protocol_name.as_str(),
            cipher.cipher_name.as_str(),
            cipher.key_exchange.as_deref().unwrap_or("N/A"),
            cipher.authentication.as_deref().unwrap_or("N/A"),
            cipher.encryption.as_deref().unwrap_or("N/A"),
            cipher.mac.as_deref().unwrap_or("N/A"),
            cipher
                .bits
                .map(|bits| bits.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            cipher.forward_secrecy,
            cipher.strength
        )
    }
}
