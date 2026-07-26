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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RenegotiationSupport {
    SecureRenegotiation,
    InsecureRenegotiation,
    ClientInitiatedDisabled,
    NotSupported,
    Inconclusive,
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
