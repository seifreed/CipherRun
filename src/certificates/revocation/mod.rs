// Certificate Revocation Checker - Check certificate revocation status via OCSP and CRL

mod crl;
mod ocsp;
mod stapling;

use super::parser::CertificateInfo;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Revocation check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationResult {
    pub status: RevocationStatus,
    pub method: RevocationMethod,
    pub details: String,
    pub ocsp_stapling: bool,
    pub ocsp_stapling_details: Option<OcspStaplingResult>,
    pub must_staple: bool,
}

/// Revocation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown,
    Error,
    NotChecked,
}

/// Revocation checking method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationMethod {
    OCSP,
    CRL,
    OCSPStapling,
    None,
}

/// OCSP Stapling detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspStaplingResult {
    /// Whether OCSP stapling is supported by the server
    pub stapling_supported: bool,
    /// Whether a stapled OCSP response was provided
    pub stapled_response_present: bool,
    /// Whether the stapled response is valid (if present)
    pub stapled_response_valid: Option<bool>,
    /// Details about the detection
    pub details: String,
}

/// Certificate revocation checker
pub struct RevocationChecker {
    pub(crate) check_timeout: Duration,
    pub(crate) phone_out_enabled: bool,
}

impl RevocationChecker {
    /// Create new revocation checker
    pub fn new(phone_out_enabled: bool) -> Self {
        Self {
            check_timeout: Duration::from_secs(10),
            phone_out_enabled,
        }
    }

    /// Check if phone-out is enabled
    pub fn is_phone_out_enabled(&self) -> bool {
        self.phone_out_enabled
    }

    /// Check revocation status for a certificate
    pub async fn check_revocation_status(
        &self,
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
    ) -> Result<RevocationResult> {
        // If phone-out is disabled, skip actual checks
        if !self.phone_out_enabled {
            return Ok(RevocationResult {
                status: RevocationStatus::NotChecked,
                method: RevocationMethod::None,
                details: "Phone-out disabled, revocation checking skipped".to_string(),
                ocsp_stapling: false,
                ocsp_stapling_details: None,
                must_staple: self.check_must_staple(cert)?,
            });
        }

        // Check OCSP Must-Staple extension
        let must_staple = self.check_must_staple(cert)?;
        let mut failed_methods = Vec::new();

        // Try OCSP first (faster and preferred)
        if let Some(ocsp_url) = self.extract_ocsp_url(cert)? {
            match self.check_ocsp(cert, issuer, &ocsp_url).await {
                Ok(status) => {
                    return Ok(RevocationResult {
                        status,
                        method: RevocationMethod::OCSP,
                        details: format!("OCSP check via {}", ocsp_url),
                        ocsp_stapling: false,
                        ocsp_stapling_details: None,
                        must_staple,
                    });
                }
                Err(e) => {
                    tracing::debug!("OCSP check failed: {}, falling back to CRL", e);
                    failed_methods.push((RevocationMethod::OCSP, e.to_string()));
                }
            }
        }

        // Fallback to CRL if OCSP fails
        if let Some(crl_url) = self.extract_crl_url(cert)? {
            match self.check_crl(cert, &crl_url).await {
                Ok(status) => {
                    return Ok(RevocationResult {
                        status,
                        method: RevocationMethod::CRL,
                        details: format!("CRL check via {}", crl_url),
                        ocsp_stapling: false,
                        ocsp_stapling_details: None,
                        must_staple,
                    });
                }
                Err(e) => {
                    tracing::debug!("CRL check failed: {}", e);
                    failed_methods.push((RevocationMethod::CRL, e.to_string()));
                }
            }
        }

        // If both methods unavailable or failed
        Ok(Self::unresolved_revocation_result(
            must_staple,
            &failed_methods,
        ))
    }

    fn unresolved_revocation_result(
        must_staple: bool,
        failed_methods: &[(RevocationMethod, String)],
    ) -> RevocationResult {
        if failed_methods.is_empty() {
            return RevocationResult {
                status: RevocationStatus::Unknown,
                method: RevocationMethod::None,
                details: "No revocation checking method available".to_string(),
                ocsp_stapling: false,
                ocsp_stapling_details: None,
                must_staple,
            };
        }

        let attempted = failed_methods
            .iter()
            .map(|(method, err)| format!("{method:?}: {err}"))
            .collect::<Vec<_>>()
            .join("; ");

        RevocationResult {
            status: RevocationStatus::Error,
            method: RevocationMethod::None,
            details: format!("All revocation checking methods failed ({attempted})"),
            ocsp_stapling: false,
            ocsp_stapling_details: None,
            must_staple,
        }
    }
}

impl RevocationResult {
    /// Get human-readable summary
    pub fn summary(&self) -> String {
        match self.status {
            RevocationStatus::Good => "Certificate is not revoked".to_string(),
            RevocationStatus::Revoked => "Certificate has been REVOKED".to_string(),
            RevocationStatus::Unknown => "Revocation status unknown".to_string(),
            RevocationStatus::Error => "Error checking revocation status".to_string(),
            RevocationStatus::NotChecked => "Revocation status not checked".to_string(),
        }
    }

    /// Check if status indicates a problem
    pub fn is_problematic(&self) -> bool {
        matches!(
            self.status,
            RevocationStatus::Revoked | RevocationStatus::Error
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_checker_creation() {
        let checker = RevocationChecker::new(true);
        assert!(checker.phone_out_enabled);
    }

    #[tokio::test]
    async fn test_disabled_phone_out() {
        let checker = RevocationChecker::new(false);
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            expiry_countdown: Some("expires in 1 year".to_string()),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec![],
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
        };

        let result = checker
            .check_revocation_status(&cert, None)
            .await
            .expect("test assertion should succeed");
        assert_eq!(result.status, RevocationStatus::NotChecked);
        assert_eq!(result.method, RevocationMethod::None);
    }

    #[test]
    fn test_revocation_result_summary_and_problematic() {
        let good = RevocationResult {
            status: RevocationStatus::Good,
            method: RevocationMethod::OCSP,
            details: "ok".to_string(),
            ocsp_stapling: false,
            ocsp_stapling_details: None,
            must_staple: false,
        };
        assert!(good.summary().contains("not revoked"));
        assert!(!good.is_problematic());

        let revoked = RevocationResult {
            status: RevocationStatus::Revoked,
            method: RevocationMethod::CRL,
            details: "revoked".to_string(),
            ocsp_stapling: false,
            ocsp_stapling_details: None,
            must_staple: false,
        };
        assert!(revoked.summary().contains("REVOKED"));
        assert!(revoked.is_problematic());

        let error = RevocationResult {
            status: RevocationStatus::Error,
            method: RevocationMethod::OCSP,
            details: "error".to_string(),
            ocsp_stapling: false,
            ocsp_stapling_details: None,
            must_staple: false,
        };
        assert!(error.summary().contains("Error"));
        assert!(error.is_problematic());
    }

    #[test]
    fn test_revocation_result_summary_not_checked() {
        let result = RevocationResult {
            status: RevocationStatus::NotChecked,
            method: RevocationMethod::None,
            details: "not checked".to_string(),
            ocsp_stapling: false,
            ocsp_stapling_details: None,
            must_staple: false,
        };
        assert!(result.summary().contains("not checked"));
        assert!(!result.is_problematic());
    }

    #[test]
    fn test_unresolved_revocation_without_methods_stays_unknown() {
        let result = RevocationChecker::unresolved_revocation_result(false, &[]);

        assert_eq!(result.status, RevocationStatus::Unknown);
        assert_eq!(result.method, RevocationMethod::None);
        assert!(result.details.contains("No revocation checking method"));
    }

    #[test]
    fn test_unresolved_revocation_with_failed_methods_is_error() {
        let failures = vec![
            (RevocationMethod::OCSP, "timeout".to_string()),
            (RevocationMethod::CRL, "bad status".to_string()),
        ];

        let result = RevocationChecker::unresolved_revocation_result(true, &failures);

        assert_eq!(result.status, RevocationStatus::Error);
        assert_eq!(result.method, RevocationMethod::None);
        assert!(result.must_staple);
        assert!(result.is_problematic());
        assert!(result.details.contains("OCSP"));
        assert!(result.details.contains("CRL"));
    }
}
