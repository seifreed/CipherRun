// Certificate Change Detector

use crate::certificates::parser::CertificateInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Types of certificate changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    NewCertificate,
    Renewal,                  // Same issuer, new serial
    IssuerChange,             // Different issuer
    KeySizeChange,            // Different key size
    SignatureAlgorithmChange, // Different signature algorithm
    SANChange,                // SAN domains changed
    ExpiryExtended,           // Expiry date extended
    ExpiryShortened,          // Expiry date shortened
}

/// Severity of certificate change
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChangeSeverity {
    Info,     // Routine renewal
    Low,      // Expiry extended
    Medium,   // SAN change
    High,     // Key size change
    Critical, // Issuer change (potential compromise)
}

impl std::fmt::Display for ChangeSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeSeverity::Info => write!(f, "Info"),
            ChangeSeverity::Low => write!(f, "Low"),
            ChangeSeverity::Medium => write!(f, "Medium"),
            ChangeSeverity::High => write!(f, "High"),
            ChangeSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Certificate change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEvent {
    pub change_type: ChangeType,
    pub severity: ChangeSeverity,
    pub description: String,
    pub previous_value: Option<String>,
    pub current_value: Option<String>,
    pub detected_at: DateTime<Utc>,
}

/// Certificate change detector
pub struct ChangeDetector {}

impl ChangeDetector {
    /// Create new change detector
    pub fn new() -> Self {
        Self {}
    }

    fn normalized_san_set(sans: &[String]) -> HashSet<String> {
        sans.iter()
            .map(|san| san.trim_end_matches('.').to_ascii_lowercase())
            .collect()
    }

    /// Detect changes between two certificates
    pub fn detect_changes(
        &self,
        previous: &CertificateInfo,
        current: &CertificateInfo,
    ) -> Vec<ChangeEvent> {
        let mut changes = Vec::new();
        let now = Utc::now();

        // Check issuer change first — independent of serial, because a rogue CA
        // could re-issue a cert with the same serial under a different issuer.
        if previous.issuer != current.issuer {
            changes.push(ChangeEvent {
                change_type: ChangeType::IssuerChange,
                severity: ChangeSeverity::Critical,
                description: "Certificate issuer changed - possible security compromise"
                    .to_string(),
                previous_value: Some(previous.issuer.clone()),
                current_value: Some(current.issuer.clone()),
                detected_at: now,
            });
        } else if previous.serial_number != current.serial_number {
            // Same issuer, new serial = routine renewal
            changes.push(ChangeEvent {
                change_type: ChangeType::Renewal,
                severity: ChangeSeverity::Info,
                description: "Certificate renewed with new serial number".to_string(),
                previous_value: Some(previous.serial_number.clone()),
                current_value: Some(current.serial_number.clone()),
                detected_at: now,
            });
        }

        // I6 fix: suppress key-size and signature-algorithm change events when
        // the certificate was replaced entirely (issuer change or renewal).
        // In those cases the IssuerChange/Renewal event already describes the
        // transition; emitting an additional KeySizeChange produces redundant
        // alerts for a single replacement.
        let same_cert_identity =
            previous.issuer == current.issuer && previous.serial_number == current.serial_number;

        if same_cert_identity && previous.public_key_size != current.public_key_size {
            changes.push(ChangeEvent {
                change_type: ChangeType::KeySizeChange,
                severity: ChangeSeverity::High,
                description: "Public key size changed".to_string(),
                previous_value: Some(format!("{} bits", previous.public_key_size.unwrap_or(0))),
                current_value: Some(format!("{} bits", current.public_key_size.unwrap_or(0))),
                detected_at: now,
            });
        }

        // Check signature algorithm change (only when cert identity is stable,
        // for the same reason as KeySizeChange above).
        if same_cert_identity && previous.signature_algorithm != current.signature_algorithm {
            changes.push(ChangeEvent {
                change_type: ChangeType::SignatureAlgorithmChange,
                severity: ChangeSeverity::Medium,
                description: "Signature algorithm changed".to_string(),
                previous_value: Some(previous.signature_algorithm.clone()),
                current_value: Some(current.signature_algorithm.clone()),
                detected_at: now,
            });
        }

        // Check SAN changes
        let prev_sans = Self::normalized_san_set(&previous.san);
        let curr_sans = Self::normalized_san_set(&current.san);

        if prev_sans != curr_sans {
            let added: Vec<_> = curr_sans.difference(&prev_sans).collect();
            let removed: Vec<_> = prev_sans.difference(&curr_sans).collect();

            let mut description = String::from("Subject Alternative Names changed");
            if !added.is_empty() {
                description.push_str(&format!(" (added: {})", added.len()));
            }
            if !removed.is_empty() {
                description.push_str(&format!(" (removed: {})", removed.len()));
            }

            changes.push(ChangeEvent {
                change_type: ChangeType::SANChange,
                severity: ChangeSeverity::Medium,
                description,
                previous_value: Some(format!("{} domains", prev_sans.len())),
                current_value: Some(format!("{} domains", curr_sans.len())),
                detected_at: now,
            });
        }

        // Check expiry date changes
        if previous.not_after != current.not_after {
            // Parse dates to determine if extended or shortened
            let is_extended = {
                let parse_date = |s: &str| -> Option<chrono::DateTime<chrono::Utc>> {
                    use chrono::NaiveDateTime;
                    // Try RFC3339: "2025-01-01T00:00:00Z"
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                        return Some(dt.with_timezone(&chrono::Utc));
                    }
                    // Try "YYYY-MM-DD HH:MM:SS UTC" format
                    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S UTC") {
                        return Some(dt.and_utc());
                    }
                    // Try without timezone suffix
                    let cleaned = s.replace(" UTC", "").replace(" GMT", "");
                    if let Ok(dt) = NaiveDateTime::parse_from_str(&cleaned, "%Y-%m-%d %H:%M:%S") {
                        return Some(dt.and_utc());
                    }
                    // Try ISO format with offset: "2025-01-01 00:00:00 +0000"
                    if let Ok(dt) = chrono::DateTime::parse_from_str(
                        &format!("{} +0000", s),
                        "%Y-%m-%d %H:%M:%S %z",
                    ) {
                        return Some(dt.with_timezone(&chrono::Utc));
                    }
                    // Try OpenSSL format: "Jan  1 00:00:00 2025 GMT"
                    if s.ends_with(" GMT") || s.ends_with(" UTC") {
                        let without_tz = s.replace(" GMT", "").replace(" UTC", "");
                        if let Ok(dt) =
                            NaiveDateTime::parse_from_str(&without_tz, "%b %d %H:%M:%S %Y")
                        {
                            return Some(dt.and_utc());
                        }
                    }
                    None
                };
                match (
                    parse_date(&previous.not_after),
                    parse_date(&current.not_after),
                ) {
                    (Some(prev), Some(curr)) => Some(curr > prev),
                    _ => {
                        // Cannot reliably compare dates — skip emitting a directional change event
                        tracing::warn!(
                            "Could not parse certificate dates for comparison: '{}' vs '{}', skipping expiry direction detection",
                            previous.not_after,
                            current.not_after
                        );
                        None
                    }
                }
            };

            if let Some(is_extended) = is_extended {
                if is_extended {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::ExpiryExtended,
                        severity: ChangeSeverity::Low,
                        description: "Certificate expiry date extended".to_string(),
                        previous_value: Some(previous.not_after.clone()),
                        current_value: Some(current.not_after.clone()),
                        detected_at: now,
                    });
                } else {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::ExpiryShortened,
                        severity: ChangeSeverity::Medium,
                        description: "Certificate expiry date shortened".to_string(),
                        previous_value: Some(previous.not_after.clone()),
                        current_value: Some(current.not_after.clone()),
                        detected_at: now,
                    });
                }
            }
        }

        changes
    }

    /// Classify severity of a change type
    pub fn classify_severity(&self, change_type: &ChangeType) -> ChangeSeverity {
        match change_type {
            ChangeType::NewCertificate => ChangeSeverity::Info,
            ChangeType::Renewal => ChangeSeverity::Info,
            ChangeType::IssuerChange => ChangeSeverity::Critical,
            ChangeType::KeySizeChange => ChangeSeverity::High,
            ChangeType::SignatureAlgorithmChange => ChangeSeverity::Medium,
            ChangeType::SANChange => ChangeSeverity::Medium,
            ChangeType::ExpiryExtended => ChangeSeverity::Low,
            ChangeType::ExpiryShortened => ChangeSeverity::Medium,
        }
    }

    /// Check if change requires immediate alert
    pub fn requires_immediate_alert(&self, change: &ChangeEvent) -> bool {
        matches!(
            change.severity,
            ChangeSeverity::Critical | ChangeSeverity::High
        )
    }

    /// Get the most severe change from a list
    pub fn most_severe<'a>(&self, changes: &'a [ChangeEvent]) -> Option<&'a ChangeEvent> {
        changes.iter().max_by_key(|c| c.severity)
    }
}

impl Default for ChangeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cert(
        serial: &str,
        issuer: &str,
        key_size: Option<usize>,
        sans: Vec<String>,
    ) -> CertificateInfo {
        CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: issuer.to_string(),
            serial_number: serial.to_string(),
            not_before: "2024-01-01 00:00:00 UTC".to_string(),
            not_after: "2025-01-01 00:00:00 UTC".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: key_size,
            rsa_exponent: Some("e 65537".to_string()),
            san: sans,
            is_ca: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            certificate_transparency: None,
            der_bytes: vec![],
        }
    }

    #[test]
    fn test_detect_renewal() {
        let detector = ChangeDetector::new();

        let previous = create_test_cert("123", "CN=Let's Encrypt", Some(2048), vec![]);
        let current = create_test_cert("456", "CN=Let's Encrypt", Some(2048), vec![]);

        let changes = detector.detect_changes(&previous, &current);

        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].change_type, ChangeType::Renewal));
        assert_eq!(changes[0].severity, ChangeSeverity::Info);
    }

    #[test]
    fn test_detect_issuer_change() {
        let detector = ChangeDetector::new();

        let previous = create_test_cert("123", "CN=Let's Encrypt", Some(2048), vec![]);
        let current = create_test_cert("456", "CN=DigiCert", Some(2048), vec![]);

        let changes = detector.detect_changes(&previous, &current);

        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].change_type, ChangeType::IssuerChange));
        assert_eq!(changes[0].severity, ChangeSeverity::Critical);
    }

    #[test]
    fn test_detect_key_size_change() {
        let detector = ChangeDetector::new();

        let previous = create_test_cert("123", "CN=Let's Encrypt", Some(2048), vec![]);
        let current = create_test_cert("123", "CN=Let's Encrypt", Some(4096), vec![]);

        let changes = detector.detect_changes(&previous, &current);

        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].change_type, ChangeType::KeySizeChange));
        assert_eq!(changes[0].severity, ChangeSeverity::High);
    }

    #[test]
    fn test_issuer_change_suppresses_key_size_change_event() {
        // I6 regression: when the certificate is replaced (new issuer + new
        // serial), the IssuerChange event is sufficient. Emitting an extra
        // KeySizeChange is redundant and inflates alert counts.
        let detector = ChangeDetector::new();
        let previous = create_test_cert("123", "CN=Let's Encrypt", Some(2048), vec![]);
        let current = create_test_cert("456", "CN=DigiCert", Some(4096), vec![]);

        let changes = detector.detect_changes(&previous, &current);

        assert!(
            changes
                .iter()
                .any(|c| matches!(c.change_type, ChangeType::IssuerChange)),
            "IssuerChange must be emitted"
        );
        assert!(
            !changes
                .iter()
                .any(|c| matches!(c.change_type, ChangeType::KeySizeChange)),
            "KeySizeChange must be suppressed when cert identity changed"
        );
    }

    #[test]
    fn test_renewal_suppresses_key_size_change_event() {
        let detector = ChangeDetector::new();
        let previous = create_test_cert("123", "CN=Let's Encrypt", Some(2048), vec![]);
        let current = create_test_cert("456", "CN=Let's Encrypt", Some(4096), vec![]);

        let changes = detector.detect_changes(&previous, &current);

        assert!(
            changes
                .iter()
                .any(|c| matches!(c.change_type, ChangeType::Renewal))
        );
        assert!(
            !changes
                .iter()
                .any(|c| matches!(c.change_type, ChangeType::KeySizeChange)),
            "KeySizeChange must be suppressed on routine renewal"
        );
    }

    #[test]
    fn test_detect_san_change() {
        let detector = ChangeDetector::new();

        let previous = create_test_cert(
            "123",
            "CN=Let's Encrypt",
            Some(2048),
            vec!["example.com".to_string(), "www.example.com".to_string()],
        );
        let current = create_test_cert(
            "123",
            "CN=Let's Encrypt",
            Some(2048),
            vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
                "api.example.com".to_string(),
            ],
        );

        let changes = detector.detect_changes(&previous, &current);

        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].change_type, ChangeType::SANChange));
        assert_eq!(changes[0].severity, ChangeSeverity::Medium);
    }

    #[test]
    fn test_san_case_only_changes_do_not_emit_change() {
        let detector = ChangeDetector::new();

        let previous = create_test_cert(
            "123",
            "CN=Let's Encrypt",
            Some(2048),
            vec!["WWW.Example.COM".to_string()],
        );
        let current = create_test_cert(
            "123",
            "CN=Let's Encrypt",
            Some(2048),
            vec!["www.example.com".to_string()],
        );

        let changes = detector.detect_changes(&previous, &current);

        assert!(changes.is_empty(), "{changes:?}");
    }

    #[test]
    fn test_classify_severity() {
        let detector = ChangeDetector::new();

        assert_eq!(
            detector.classify_severity(&ChangeType::NewCertificate),
            ChangeSeverity::Info
        );
        assert_eq!(
            detector.classify_severity(&ChangeType::Renewal),
            ChangeSeverity::Info
        );
        assert_eq!(
            detector.classify_severity(&ChangeType::IssuerChange),
            ChangeSeverity::Critical
        );
        assert_eq!(
            detector.classify_severity(&ChangeType::KeySizeChange),
            ChangeSeverity::High
        );
        assert_eq!(
            detector.classify_severity(&ChangeType::SANChange),
            ChangeSeverity::Medium
        );
    }

    #[test]
    fn test_requires_immediate_alert() {
        let detector = ChangeDetector::new();

        let critical_event = ChangeEvent {
            change_type: ChangeType::IssuerChange,
            severity: ChangeSeverity::Critical,
            description: "Test".to_string(),
            previous_value: None,
            current_value: None,
            detected_at: Utc::now(),
        };

        let info_event = ChangeEvent {
            change_type: ChangeType::Renewal,
            severity: ChangeSeverity::Info,
            description: "Test".to_string(),
            previous_value: None,
            current_value: None,
            detected_at: Utc::now(),
        };

        assert!(detector.requires_immediate_alert(&critical_event));
        assert!(!detector.requires_immediate_alert(&info_event));
    }

    #[test]
    fn test_most_severe() {
        let detector = ChangeDetector::new();

        let changes = vec![
            ChangeEvent {
                change_type: ChangeType::Renewal,
                severity: ChangeSeverity::Info,
                description: "Test1".to_string(),
                previous_value: None,
                current_value: None,
                detected_at: Utc::now(),
            },
            ChangeEvent {
                change_type: ChangeType::IssuerChange,
                severity: ChangeSeverity::Critical,
                description: "Test2".to_string(),
                previous_value: None,
                current_value: None,
                detected_at: Utc::now(),
            },
            ChangeEvent {
                change_type: ChangeType::SANChange,
                severity: ChangeSeverity::Medium,
                description: "Test3".to_string(),
                previous_value: None,
                current_value: None,
                detected_at: Utc::now(),
            },
        ];

        let most_severe = detector.most_severe(&changes);
        assert!(most_severe.is_some());
        assert_eq!(most_severe.unwrap().severity, ChangeSeverity::Critical);
    }

    #[test]
    fn test_detect_expiry_extended() {
        let detector = ChangeDetector::new();
        let mut previous = create_test_cert("123", "CN=Let's Encrypt", Some(2048), vec![]);
        let mut current = previous.clone();
        previous.not_after = "2025-01-01 00:00:00 UTC".to_string();
        current.not_after = "2026-01-01 00:00:00 UTC".to_string();

        let changes = detector.detect_changes(&previous, &current);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c.change_type, ChangeType::ExpiryExtended))
        );
    }
}
