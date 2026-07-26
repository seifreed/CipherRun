/// Result of insecure renegotiation detection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InsecureRenegotiationResult {
    /// Server appears vulnerable to insecure renegotiation.
    Detected,
    /// Server responded without renegotiation_info extension; manual
    /// verification is needed to determine if CVE-2009-3555 applies.
    Inconclusive,
    /// Server properly rejected or has secure renegotiation.
    NotDetected,
}

impl InsecureRenegotiationResult {
    pub(super) fn merge(self, next: Self) -> Self {
        match (self, next) {
            (Self::Detected, _) | (_, Self::Detected) => Self::Detected,
            (Self::Inconclusive, _) | (_, Self::Inconclusive) => Self::Inconclusive,
            _ => Self::NotDetected,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RenegotiationSupport {
    SecureRenegotiation,
    InsecureRenegotiation,
    ClientInitiatedDisabled,
    NotSupported,
    Inconclusive,
}

impl RenegotiationSupport {
    pub(super) fn merge(self, next: Self) -> Self {
        match (self, next) {
            (Self::SecureRenegotiation, _) | (_, Self::SecureRenegotiation) => {
                Self::SecureRenegotiation
            }
            (Self::InsecureRenegotiation, _) | (_, Self::InsecureRenegotiation) => {
                Self::InsecureRenegotiation
            }
            (Self::Inconclusive, _) | (_, Self::Inconclusive) => Self::Inconclusive,
            (Self::ClientInitiatedDisabled, _) | (_, Self::ClientInitiatedDisabled) => {
                Self::ClientInitiatedDisabled
            }
            _ => Self::NotSupported,
        }
    }
}

pub(super) fn merge_secure_extension_probe(
    current: Option<bool>,
    next: Option<bool>,
) -> Option<bool> {
    match (current, next) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, _) | (_, None) => None,
        _ => Some(false),
    }
}

/// Renegotiation test result.
#[derive(Debug, Clone)]
pub struct RenegotiationTestResult {
    pub support: RenegotiationSupport,
    pub secure_extension: bool,
    pub vulnerable: bool,
    pub inconclusive: bool,
    /// Indicates the test result is inconclusive and requires manual verification.
    pub needs_verification: bool,
    pub details: String,
}
