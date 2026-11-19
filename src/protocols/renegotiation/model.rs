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

#[cfg(test)]
mod tests {
    use super::{
        InsecureRenegotiationResult as Insecure, RenegotiationSupport as Support,
        merge_secure_extension_probe,
    };

    #[test]
    fn insecure_renegotiation_merge_preserves_the_most_severe_result() {
        let outcomes = [
            Insecure::Detected,
            Insecure::Inconclusive,
            Insecure::NotDetected,
        ];
        for current in outcomes {
            for next in outcomes {
                let expected = if current == Insecure::Detected || next == Insecure::Detected {
                    Insecure::Detected
                } else if current == Insecure::Inconclusive || next == Insecure::Inconclusive {
                    Insecure::Inconclusive
                } else {
                    Insecure::NotDetected
                };
                assert_eq!(current.merge(next), expected);
            }
        }
    }

    #[test]
    fn support_merge_uses_the_documented_precedence() {
        let outcomes = [
            Support::SecureRenegotiation,
            Support::InsecureRenegotiation,
            Support::Inconclusive,
            Support::ClientInitiatedDisabled,
            Support::NotSupported,
        ];
        for current in outcomes {
            for next in outcomes {
                let expected = if current == Support::SecureRenegotiation
                    || next == Support::SecureRenegotiation
                {
                    Support::SecureRenegotiation
                } else if current == Support::InsecureRenegotiation
                    || next == Support::InsecureRenegotiation
                {
                    Support::InsecureRenegotiation
                } else if current == Support::Inconclusive || next == Support::Inconclusive {
                    Support::Inconclusive
                } else if current == Support::ClientInitiatedDisabled
                    || next == Support::ClientInitiatedDisabled
                {
                    Support::ClientInitiatedDisabled
                } else {
                    Support::NotSupported
                };
                assert_eq!(current.merge(next), expected);
            }
        }
    }

    #[test]
    fn secure_extension_merge_prioritizes_positive_then_unknown() {
        let outcomes = [Some(true), Some(false), None];
        for current in outcomes {
            for next in outcomes {
                let expected = if current == Some(true) || next == Some(true) {
                    Some(true)
                } else if current.is_none() || next.is_none() {
                    None
                } else {
                    Some(false)
                };
                assert_eq!(merge_secure_extension_probe(current, next), expected);
            }
        }
    }
}
