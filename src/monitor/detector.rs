// Certificate Change Detector

use crate::certificates::parser::CertificateInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

    /// Detect changes between two certificates
    pub fn detect_changes(
        &self,
        previous: &CertificateInfo,
        current: &CertificateInfo,
    ) -> Vec<ChangeEvent> {
        let mut changes = Vec::new();
        let now = Utc::now();

        // Check serial number change (indicates renewal or replacement)
        if previous.serial_number != current.serial_number {
            // Check if issuer is the same (renewal) or different (issuer change)
            if previous.issuer == current.issuer {
                changes.push(ChangeEvent {
                    change_type: ChangeType::Renewal,
                    severity: ChangeSeverity::Info,
                    description: "Certificate renewed with new serial number".to_string(),
                    previous_value: Some(previous.serial_number.clone()),
                    current_value: Some(current.serial_number.clone()),
                    detected_at: now,
                });
            } else {
                changes.push(ChangeEvent {
                    change_type: ChangeType::IssuerChange,
                    severity: ChangeSeverity::Critical,
                    description: "Certificate issuer changed - possible security compromise"
                        .to_string(),
                    previous_value: Some(previous.issuer.clone()),
                    current_value: Some(current.issuer.clone()),
                    detected_at: now,
                });
            }
        }

        // Check key size change
        if previous.public_key_size != current.public_key_size {
            changes.push(ChangeEvent {
                change_type: ChangeType::KeySizeChange,
                severity: ChangeSeverity::High,
                description: "Public key size changed".to_string(),
                previous_value: Some(format!("{} bits", previous.public_key_size.unwrap_or(0))),
                current_value: Some(format!("{} bits", current.public_key_size.unwrap_or(0))),
                detected_at: now,
            });
        }

        // Check signature algorithm change
        if previous.signature_algorithm != current.signature_algorithm {
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
        let prev_sans: std::collections::HashSet<_> = previous.san.iter().collect();
        let curr_sans: std::collections::HashSet<_> = current.san.iter().collect();

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
            // For now, do simple string comparison
            let is_extended = current.not_after > previous.not_after;

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
}
