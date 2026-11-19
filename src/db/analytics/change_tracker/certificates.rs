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

        Ok(detect_certificate_changes_between(cert1, cert2, timestamp))
    }
}

fn detect_certificate_changes_between(
    cert1: Option<crate::db::CertificateRecord>,
    cert2: Option<crate::db::CertificateRecord>,
    timestamp: DateTime<Utc>,
) -> Vec<ChangeEvent> {
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

    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::CertificateRecord;
    use chrono::TimeZone;

    fn certificate(fingerprint: &str) -> CertificateRecord {
        let start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        CertificateRecord::new(
            fingerprint.to_string(),
            "CN=example.com".to_string(),
            "CN=Example CA".to_string(),
            start,
            end,
            false,
        )
    }

    #[test]
    fn certificate_presence_and_unchanged_fingerprint_are_classified() {
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();

        assert!(detect_certificate_changes_between(None, None, timestamp).is_empty());

        let added = detect_certificate_changes_between(None, Some(certificate("new")), timestamp);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].description, "Certificate added");
        assert_eq!(added[0].severity, ChangeSeverity::Low);
        assert_eq!(added[0].current_value.as_deref(), Some("present"));
        assert_eq!(added[0].timestamp, timestamp);

        let removed = detect_certificate_changes_between(Some(certificate("old")), None, timestamp);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].description, "Certificate removed");
        assert_eq!(removed[0].severity, ChangeSeverity::Critical);
        assert_eq!(removed[0].previous_value.as_deref(), Some("present"));

        let unchanged = detect_certificate_changes_between(
            Some(certificate("same")),
            Some(certificate("same")),
            timestamp,
        );
        assert!(unchanged.is_empty());

        let same_properties = detect_certificate_changes_between(
            Some(certificate("old")),
            Some(certificate("new")),
            timestamp,
        );
        assert_eq!(same_properties.len(), 1);
        assert_eq!(
            same_properties[0].description,
            "Certificate renewed or replaced"
        );
    }

    #[test]
    fn certificate_replacement_reports_issuer_key_and_validity_changes() {
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        let mut old = certificate("old");
        old.public_key_size = Some(4096);
        let mut new = certificate("new");
        new.subject = "CN=renewed.example.com".to_string();
        new.issuer = "CN=New CA".to_string();
        new.public_key_size = Some(2048);
        new.not_after = Utc.with_ymd_and_hms(2025, 12, 1, 0, 0, 0).unwrap();

        let changes = detect_certificate_changes_between(Some(old), Some(new), timestamp);
        assert_eq!(changes.len(), 4);
        assert_eq!(changes[0].description, "Certificate renewed or replaced");
        assert_eq!(changes[0].previous_value.as_deref(), Some("CN=example.com"));
        assert_eq!(
            changes[0].current_value.as_deref(),
            Some("CN=renewed.example.com")
        );
        assert_eq!(changes[1].description, "Certificate issuer changed");
        assert_eq!(changes[1].severity, ChangeSeverity::High);
        assert_eq!(changes[2].description, "Certificate key size changed");
        assert_eq!(changes[2].severity, ChangeSeverity::High);
        assert_eq!(changes[3].description, "Certificate validity shortened");
        assert_eq!(changes[3].severity, ChangeSeverity::High);
        assert!(changes.iter().all(|change| change.timestamp == timestamp));
    }

    #[test]
    fn certificate_key_size_and_validity_improvements_are_reported() {
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        let mut old = certificate("old");
        old.public_key_size = Some(2048);
        let mut new = certificate("new");
        new.public_key_size = Some(4096);
        new.not_after = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();

        let changes = detect_certificate_changes_between(Some(old), Some(new), timestamp);
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[1].description, "Certificate key size changed");
        assert_eq!(changes[1].severity, ChangeSeverity::Low);
        assert_eq!(changes[2].description, "Certificate validity extended");
        assert_eq!(changes[2].severity, ChangeSeverity::Info);
    }

    #[test]
    fn certificate_key_size_unknown_transition_uses_medium_severity() {
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        let old = certificate("old");
        let mut new = certificate("new");
        new.public_key_size = Some(2048);

        let changes = detect_certificate_changes_between(Some(old), Some(new), timestamp);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[1].description, "Certificate key size changed");
        assert_eq!(changes[1].severity, ChangeSeverity::Medium);
        assert_eq!(changes[1].previous_value, None);
        assert_eq!(changes[1].current_value.as_deref(), Some("2048 bits"));
    }
}
