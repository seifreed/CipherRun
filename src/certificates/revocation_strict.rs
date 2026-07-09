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
                // Hard-fail on revoked certificates (most critical)
                if self.hard_fail_mode && matches!(result.status, RevocationStatus::Revoked) {
                    return Err(crate::TlsError::InvalidHandshake {
                        details: format!(
                            "Hard fail mode: certificate is revoked: {}",
                            result.details
                        ),
                    });
                }

                // Hard-fail on definite errors (check failed)
                if self.hard_fail_mode && matches!(result.status, RevocationStatus::Error) {
                    return Err(crate::TlsError::InvalidHandshake {
                        details: format!(
                            "Hard fail mode: revocation check failed with error: {}",
                            result.details
                        ),
                    });
                }

                // Hard-fail on unknown status (OCSP/CRL unreachable)
                if self.hard_fail_mode && matches!(result.status, RevocationStatus::Unknown) {
                    return Err(crate::TlsError::InvalidHandshake {
                        details: "Hard fail mode: revocation status unknown - OCSP/CRL check inconclusive".to_string(),
                    });
                }

                Ok(StrictRevocationResult {
                    base_result: result,
                    hard_fail_mode_enabled: self.hard_fail_mode,
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
                    Ok(self.soft_fail_result(cert, e.to_string()))
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
                    results.push(self.soft_fail_result(cert, e.to_string()));
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

    fn soft_fail_result(&self, cert: &CertificateInfo, error: String) -> StrictRevocationResult {
        let must_staple = self.base_checker.check_must_staple(cert).unwrap_or(false);

        StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Unknown,
                method: super::revocation::RevocationMethod::None,
                details: format!("Revocation check error (soft fail): {}", error),
                ocsp_stapling: false,
                ocsp_stapling_details: None,
                must_staple,
            },
            hard_fail_mode_enabled: false,
            error_details: Some(error),
        }
    }
}

/// Extended revocation result with hard-fail tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrictRevocationResult {
    /// The base revocation result
    pub base_result: RevocationResult,
    /// Whether hard-fail mode was enabled during this check
    pub hard_fail_mode_enabled: bool,
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
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::hash::MessageDigest as OpensslMessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

    fn cert_with_must_staple_and_malformed_aia() -> crate::certificates::parser::CertificateInfo {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "revocation.example.com")
            .unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();

        let must_staple_oid = Asn1Object::from_str("1.3.6.1.5.5.7.1.24").unwrap();
        let must_staple = Asn1OctetString::new_from_bytes(b"\x30\x03\x02\x01\x05").unwrap();
        builder
            .append_extension(
                X509Extension::new_from_der(&must_staple_oid, false, &must_staple).unwrap(),
            )
            .unwrap();

        let aia_oid = Asn1Object::from_str("1.3.6.1.5.5.7.1.1").unwrap();
        let malformed_aia = Asn1OctetString::new_from_bytes(b"\x05\x00").unwrap();
        builder
            .append_extension(X509Extension::new_from_der(&aia_oid, false, &malformed_aia).unwrap())
            .unwrap();

        builder.sign(&pkey, OpensslMessageDigest::sha256()).unwrap();

        crate::certificates::parser::CertificateInfo {
            der_bytes: builder.build().to_der().unwrap(),
            ..Default::default()
        }
    }

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

    #[tokio::test]
    async fn test_soft_fail_preserves_must_staple() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_phone_out(true)
            .with_hard_fail(false)
            .build();
        let cert = cert_with_must_staple_and_malformed_aia();

        let result = checker
            .check_revocation_with_hardfail(&cert, None)
            .await
            .expect("soft fail should return a result");

        assert!(result.is_unknown());
        assert!(result.base_result.must_staple);
        assert!(result.error_details.is_some());
    }

    #[test]
    fn test_strict_result_status_checks() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Good,
                method: super::super::revocation::RevocationMethod::OCSP,
                details: "Test".to_string(),
                ocsp_stapling: false,
                ocsp_stapling_details: None,
                must_staple: false,
            },
            hard_fail_mode_enabled: false,
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
                ocsp_stapling_details: None,
                must_staple: false,
            },
            hard_fail_mode_enabled: false,
            error_details: None,
        };

        assert!(!result.is_good());
        assert!(result.is_revoked());
        assert!(!result.is_unknown());
        assert!(!result.is_error());
    }
}
