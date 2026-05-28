// ChangeTracker certificate-change detection

use super::*;

impl ChangeTracker {
    pub(super) async fn detect_certificate_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let cert1 = self.get_leaf_certificate(scan_id_1).await?;
        let cert2 = self.get_leaf_certificate(scan_id_2).await?;

        let mut changes = Vec::new();

        match (cert1, cert2) {
            (Some(c1), Some(c2)) => {
                // Different certificate (renewal or replacement)
                if c1.fingerprint_sha256 != c2.fingerprint_sha256 {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Certificate,
                        severity: ChangeSeverity::Medium,
                        description: "Certificate renewed or replaced".to_string(),
                        previous_value: Some(c1.subject.clone()),
                        current_value: Some(c2.subject.clone()),
                        timestamp,
                    });

                    // Check issuer change
                    if c1.issuer != c2.issuer {
                        changes.push(ChangeEvent {
                            change_type: ChangeType::Certificate,
                            severity: ChangeSeverity::High,
                            description: "Certificate issuer changed".to_string(),
                            previous_value: Some(c1.issuer.clone()),
                            current_value: Some(c2.issuer.clone()),
                            timestamp,
                        });
                    }

                    // Check key size change
                    if c1.public_key_size != c2.public_key_size {
                        let severity = match (c1.public_key_size, c2.public_key_size) {
                            (Some(old), Some(new)) if new < old => ChangeSeverity::High,
                            (Some(old), Some(new)) if new > old => ChangeSeverity::Low,
                            _ => ChangeSeverity::Medium,
                        };

                        changes.push(ChangeEvent {
                            change_type: ChangeType::Certificate,
                            severity,
                            description: "Certificate key size changed".to_string(),
                            previous_value: c1.public_key_size.map(|s| format!("{} bits", s)),
                            current_value: c2.public_key_size.map(|s| format!("{} bits", s)),
                            timestamp,
                        });
                    }

                    // Check expiration extension
                    if c2.not_after > c1.not_after {
                        changes.push(ChangeEvent {
                            change_type: ChangeType::Certificate,
                            severity: ChangeSeverity::Info,
                            description: "Certificate validity extended".to_string(),
                            previous_value: Some(c1.not_after.format("%Y-%m-%d").to_string()),
                            current_value: Some(c2.not_after.format("%Y-%m-%d").to_string()),
                            timestamp,
                        });
                    } else if c2.not_after < c1.not_after {
                        changes.push(ChangeEvent {
                            change_type: ChangeType::Certificate,
                            severity: ChangeSeverity::High,
                            description: "Certificate validity shortened".to_string(),
                            previous_value: Some(c1.not_after.format("%Y-%m-%d").to_string()),
                            current_value: Some(c2.not_after.format("%Y-%m-%d").to_string()),
                            timestamp,
                        });
                    }
                }
            }
            (None, Some(_)) => {
                changes.push(ChangeEvent {
                    change_type: ChangeType::Certificate,
                    severity: ChangeSeverity::Low,
                    description: "Certificate added".to_string(),
                    previous_value: None,
                    current_value: Some("present".to_string()),
                    timestamp,
                });
            }
            (Some(_), None) => {
                changes.push(ChangeEvent {
                    change_type: ChangeType::Certificate,
                    severity: ChangeSeverity::Critical,
                    description: "Certificate removed".to_string(),
                    previous_value: Some("present".to_string()),
                    current_value: None,
                    timestamp,
                });
            }
            (None, None) => {}
        }

        Ok(changes)
    }
}
