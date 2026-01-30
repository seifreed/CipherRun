/// Strict Revocation Checking - Hard fail mode for revocation check errors
///
/// This module extends the revocation checking functionality to support strict
/// (hard fail) mode, where any error during revocation checking causes the entire
/// scan to fail. This is useful for:
/// - Strict security compliance requirements
/// - Ensuring revocation information is always available
/// - Failing fast on connectivity or infrastructure issues
/// - Meeting security standards that require successful revocation verification
use super::revocation::{RevocationChecker, RevocationResult, RevocationStatus};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use serde::{Deserialize, Serialize};

/// Strict revocation checker that can hard-fail on errors
pub struct StrictRevocationChecker {
    base_checker: RevocationChecker,
    hard_fail_mode: bool,
}

impl StrictRevocationChecker {
    /// Create a new strict revocation checker
    ///
    /// # Arguments
    /// * `phone_out_enabled` - Whether revocation checking is enabled
    /// * `hard_fail_mode` - Whether to hard-fail on revocation check errors
    ///
    /// # Returns
    /// A new StrictRevocationChecker instance
    pub fn new(phone_out_enabled: bool, hard_fail_mode: bool) -> Self {
        Self {
            base_checker: RevocationChecker::new(phone_out_enabled),
            hard_fail_mode,
        }
    }

    /// Check revocation status with optional hard-fail behavior
    ///
    /// If hard_fail_mode is enabled, any errors during revocation checking
    /// will cause this function to return an error, failing the entire scan.
    /// If hard_fail_mode is disabled, errors result in Unknown status instead.
    ///
    /// # Arguments
    /// * `cert` - The certificate to check
    /// * `issuer` - Optional issuer certificate
    ///
    /// # Returns
    /// A Result containing RevocationResult on success, or error on hard failure
    ///
    /// # Errors
    /// If hard_fail_mode is enabled and revocation checking fails, returns an error
    pub async fn check_revocation_with_hardfail(
        &self,
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
    ) -> Result<StrictRevocationResult> {
        match self
            .base_checker
            .check_revocation_status(cert, issuer)
            .await
        {
            Ok(result) => {
                // Check if the result indicates an error
                if self.hard_fail_mode && result.status == RevocationStatus::Error {
                    return Err(crate::TlsError::InvalidHandshake {
                        details: format!(
                            "Hard fail mode: revocation check failed with error: {}",
                            result.details
                        ),
                    });
                }

                Ok(StrictRevocationResult {
                    base_result: result,
                    hard_fail_applied: false,
                    error_details: None,
                })
            }
            Err(e) => {
                if self.hard_fail_mode {
                    // Hard fail: return error with details
                    Err(crate::TlsError::InvalidHandshake {
                        details: format!("Hard fail mode: revocation check error: {}", e),
                    })
                } else {
                    // Soft fail: return Unknown status
                    Ok(StrictRevocationResult {
                        base_result: RevocationResult {
                            status: RevocationStatus::Unknown,
                            method: super::revocation::RevocationMethod::None,
                            details: format!("Revocation check error (soft fail): {}", e),
                            ocsp_stapling: false,
                            must_staple: false,
                        },
                        hard_fail_applied: false,
                        error_details: Some(e.to_string()),
                    })
                }
            }
        }
    }

    /// Check revocation status for a certificate chain
    ///
    /// Processes all certificates in the chain, stopping on first hard failure
    /// if hard_fail_mode is enabled.
    ///
    /// # Arguments
    /// * `certificates` - Vector of certificates to check
    ///
    /// # Returns
    /// A vector of StrictRevocationResult for each certificate
    ///
    /// # Errors
    /// If hard_fail_mode is enabled and any certificate fails, returns error
    pub async fn check_revocation_chain(
        &self,
        certificates: &[CertificateInfo],
    ) -> Result<Vec<StrictRevocationResult>> {
        let mut results = Vec::new();

        for (i, cert) in certificates.iter().enumerate() {
            // For chain checks, use the next certificate as issuer if available
            let issuer = certificates.get(i + 1);

            match self.check_revocation_with_hardfail(cert, issuer).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    if self.hard_fail_mode {
                        return Err(e);
                    }
                    // Soft fail: continue with remaining certificates
                    results.push(StrictRevocationResult {
                        base_result: RevocationResult {
                            status: RevocationStatus::Unknown,
                            method: super::revocation::RevocationMethod::None,
                            details: format!("Chain check error (soft fail): {}", e),
                            ocsp_stapling: false,
                            must_staple: false,
                        },
                        hard_fail_applied: false,
                        error_details: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(results)
    }

    /// Check if hard-fail mode is enabled
    pub fn is_hard_fail_enabled(&self) -> bool {
        self.hard_fail_mode
    }

    /// Check if phone-out is enabled
    pub fn is_phone_out_enabled(&self) -> bool {
        self.base_checker.is_phone_out_enabled()
    }
}

/// Extended revocation result with hard-fail tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrictRevocationResult {
    /// The base revocation result
    pub base_result: RevocationResult,
    /// Whether hard-fail was applied
    pub hard_fail_applied: bool,
    /// Error details if hard-fail was triggered
    pub error_details: Option<String>,
}

impl StrictRevocationResult {
    /// Get the revocation status
    pub fn status(&self) -> RevocationStatus {
        self.base_result.status
    }

    /// Get the revocation method
    pub fn method(&self) -> super::revocation::RevocationMethod {
        self.base_result.method
    }

    /// Get the details string
    pub fn details(&self) -> &str {
        &self.base_result.details
    }

    /// Check if revocation is good
    pub fn is_good(&self) -> bool {
        self.base_result.status == RevocationStatus::Good
    }

    /// Check if certificate is revoked
    pub fn is_revoked(&self) -> bool {
        self.base_result.status == RevocationStatus::Revoked
    }

    /// Check if revocation status is unknown
    pub fn is_unknown(&self) -> bool {
        self.base_result.status == RevocationStatus::Unknown
    }

    /// Check if revocation check errored
    pub fn is_error(&self) -> bool {
        self.base_result.status == RevocationStatus::Error
    }
}

/// Builder for creating StrictRevocationChecker with fluent API
pub struct StrictRevocationCheckerBuilder {
    phone_out_enabled: bool,
    hard_fail_mode: bool,
}

impl Default for StrictRevocationCheckerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StrictRevocationCheckerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            phone_out_enabled: false,
            hard_fail_mode: false,
        }
    }

    /// Enable phone-out (revocation checking)
    pub fn with_phone_out(mut self, enabled: bool) -> Self {
        self.phone_out_enabled = enabled;
        self
    }

    /// Enable hard-fail mode
    pub fn with_hard_fail(mut self, enabled: bool) -> Self {
        self.hard_fail_mode = enabled;
        self
    }

    /// Build the checker
    pub fn build(self) -> StrictRevocationChecker {
        StrictRevocationChecker::new(self.phone_out_enabled, self.hard_fail_mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let checker = StrictRevocationCheckerBuilder::new().build();
        assert!(!checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_builder_with_hard_fail() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_hard_fail(true)
            .build();
        assert!(checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_strict_result_status_checks() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Good,
                method: super::super::revocation::RevocationMethod::OCSP,
                details: "Test".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert!(result.is_good());
        assert!(!result.is_revoked());
        assert!(!result.is_unknown());
        assert!(!result.is_error());
    }

    #[test]
    fn test_strict_result_revoked() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Revoked,
                method: super::super::revocation::RevocationMethod::OCSP,
                details: "Certificate is revoked".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert!(!result.is_good());
        assert!(result.is_revoked());
        assert!(!result.is_unknown());
        assert!(!result.is_error());
    }
}
