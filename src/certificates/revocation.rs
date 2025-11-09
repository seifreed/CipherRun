// Certificate Revocation Checker - Check certificate revocation status via OCSP and CRL

use super::parser::CertificateInfo;
use crate::Result;
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspRequest, OcspResponse, OcspResponseStatus};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;
use x509_parser::prelude::*;

/// Revocation check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationResult {
    pub status: RevocationStatus,
    pub method: RevocationMethod,
    pub details: String,
    pub ocsp_stapling: bool,
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

/// Certificate revocation checker
pub struct RevocationChecker {
    check_timeout: Duration,
    phone_out_enabled: bool,
}

impl RevocationChecker {
    /// Create new revocation checker
    pub fn new(phone_out_enabled: bool) -> Self {
        Self {
            check_timeout: Duration::from_secs(10),
            phone_out_enabled,
        }
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
                must_staple: self.check_must_staple(cert)?,
            });
        }

        // Check OCSP Must-Staple extension
        let must_staple = self.check_must_staple(cert)?;

        // Try OCSP first (faster and preferred)
        if let Some(ocsp_url) = self.extract_ocsp_url(cert)? {
            match self.check_ocsp(cert, issuer, &ocsp_url).await {
                Ok(status) => {
                    return Ok(RevocationResult {
                        status,
                        method: RevocationMethod::OCSP,
                        details: format!("OCSP check via {}", ocsp_url),
                        ocsp_stapling: false,
                        must_staple,
                    });
                }
                Err(e) => {
                    tracing::debug!("OCSP check failed: {}, falling back to CRL", e);
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
                        must_staple,
                    });
                }
                Err(e) => {
                    tracing::debug!("CRL check failed: {}", e);
                }
            }
        }

        // If both methods unavailable or failed
        Ok(RevocationResult {
            status: RevocationStatus::Unknown,
            method: RevocationMethod::None,
            details: "No revocation checking method available or all methods failed".to_string(),
            ocsp_stapling: false,
            must_staple,
        })
    }

    /// Extract OCSP responder URL from certificate
    fn extract_ocsp_url(&self, cert: &CertificateInfo) -> Result<Option<String>> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(None);
        }

        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

        // Look for Authority Information Access extension
        if let Ok(Some(ext)) =
            parsed_cert.get_extension_unique(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
            && let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension()
        {
            for access_desc in &aia.accessdescs {
                // OCSP OID: 1.3.6.1.5.5.7.48.1
                if access_desc.access_method.to_string() == "1.3.6.1.5.5.7.48.1"
                    && let GeneralName::URI(uri) = &access_desc.access_location
                {
                    return Ok(Some(uri.to_string()));
                }
            }
        }

        Ok(None)
    }

    /// Extract CRL distribution point URL from certificate
    fn extract_crl_url(&self, cert: &CertificateInfo) -> Result<Option<String>> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(None);
        }

        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

        // Look for CRL Distribution Points extension
        if let Ok(Some(ext)) =
            parsed_cert.get_extension_unique(&oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
            && let ParsedExtension::CRLDistributionPoints(crl_dp) = ext.parsed_extension()
        {
            for point in &crl_dp.points {
                if let Some(dist_point) = &point.distribution_point
                    && let x509_parser::extensions::DistributionPointName::FullName(names) =
                        dist_point
                {
                    for name in names {
                        if let GeneralName::URI(uri) = name
                            && uri.starts_with("http")
                        {
                            return Ok(Some(uri.to_string()));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Check if certificate has OCSP Must-Staple extension
    fn check_must_staple(&self, cert: &CertificateInfo) -> Result<bool> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(false);
        }

        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

        // Look for TLS Feature extension (OCSP Must-Staple)
        // OID: 1.3.6.1.5.5.7.1.24
        use der_parser::oid::Oid;
        let tls_feature_oid =
            Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 24]).map_err(|_| anyhow::anyhow!("Invalid OID"))?;

        if let Ok(Some(_ext)) = parsed_cert.get_extension_unique(&tls_feature_oid) {
            // If TLS Feature extension exists, it likely contains OCSP Must-Staple (feature 5)
            // Full parsing would require checking the extension value
            return Ok(true);
        }

        Ok(false)
    }

    /// Check OCSP revocation status
    async fn check_ocsp(
        &self,
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
        ocsp_url: &str,
    ) -> Result<RevocationStatus> {
        // Build OCSP request
        let request_body = self.build_ocsp_request(cert, issuer)?;

        // Send HTTP POST to OCSP responder
        let client = reqwest::Client::builder()
            .timeout(self.check_timeout)
            .build()?;

        let response = timeout(
            self.check_timeout,
            client
                .post(ocsp_url)
                .header("Content-Type", "application/ocsp-request")
                .body(request_body)
                .send(),
        )
        .await??;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("OCSP responder returned error: {}", response.status()).into());
        }

        let response_bytes = response.bytes().await?;

        // Parse OCSP response
        self.parse_ocsp_response(&response_bytes, cert, issuer)
    }

    /// Build OCSP request using OpenSSL
    fn build_ocsp_request(
        &self,
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
    ) -> Result<Vec<u8>> {
        // Issuer certificate is required for building OCSP requests
        let issuer_info = issuer.ok_or_else(|| {
            anyhow::anyhow!("Issuer certificate required for OCSP request")
        })?;

        // Parse certificates from DER bytes using OpenSSL
        let cert_x509 = X509::from_der(&cert.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate DER: {}", e))?;

        let issuer_x509 = X509::from_der(&issuer_info.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse issuer certificate DER: {}", e))?;

        // Create OCSP certificate ID
        // This combines the certificate serial number with hashes of the issuer's name and public key
        let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), &cert_x509, &issuer_x509)
            .map_err(|e| anyhow::anyhow!("Failed to create OCSP CertId: {}", e))?;

        // Build OCSP request
        let mut ocsp_req = OcspRequest::new()
            .map_err(|e| anyhow::anyhow!("Failed to create OCSP request: {}", e))?;

        // Add the certificate ID to the request
        ocsp_req.add_id(cert_id)
            .map_err(|e| anyhow::anyhow!("Failed to add CertId to OCSP request: {}", e))?;

        // Optionally add a nonce for replay protection (recommended but not required)
        // Some OCSP responders may not support nonces
        // ocsp_req.add_nonce()
        //     .map_err(|e| anyhow::anyhow!("Failed to add nonce to OCSP request: {}", e))?;

        // Serialize the request to DER format
        let request_der = ocsp_req.to_der()
            .map_err(|e| anyhow::anyhow!("Failed to serialize OCSP request to DER: {}", e))?;

        Ok(request_der)
    }

    /// Parse OCSP response using OpenSSL
    fn parse_ocsp_response(
        &self,
        response_bytes: &[u8],
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
    ) -> Result<RevocationStatus> {
        // Parse the OCSP response from DER bytes
        let ocsp_response = OcspResponse::from_der(response_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse OCSP response: {}", e))?;

        // Check the response status
        let response_status = ocsp_response.status();

        match response_status {
            OcspResponseStatus::SUCCESSFUL => {
                // Response is successful, extract the basic response
            }
            OcspResponseStatus::MALFORMED_REQUEST => {
                return Err(anyhow::anyhow!("OCSP responder reported malformed request").into());
            }
            OcspResponseStatus::INTERNAL_ERROR => {
                return Err(anyhow::anyhow!("OCSP responder reported internal error").into());
            }
            OcspResponseStatus::TRY_LATER => {
                return Err(anyhow::anyhow!("OCSP responder is temporarily unavailable").into());
            }
            OcspResponseStatus::SIG_REQUIRED => {
                return Err(anyhow::anyhow!("OCSP responder requires signed request").into());
            }
            OcspResponseStatus::UNAUTHORIZED => {
                return Err(anyhow::anyhow!("OCSP responder reported unauthorized request").into());
            }
            _ => {
                return Err(anyhow::anyhow!("OCSP responder returned unknown status: {:?}", response_status).into());
            }
        }

        // Get the basic response from the OCSP response
        let basic_response = ocsp_response.basic()
            .map_err(|e| anyhow::anyhow!("Failed to get basic OCSP response: {}", e))?;

        // Recreate the certificate ID to look up the status
        let issuer_info = issuer.ok_or_else(|| {
            anyhow::anyhow!("Issuer certificate required for OCSP response parsing")
        })?;

        let cert_x509 = X509::from_der(&cert.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate DER: {}", e))?;

        let issuer_x509 = X509::from_der(&issuer_info.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse issuer certificate DER: {}", e))?;

        let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), &cert_x509, &issuer_x509)
            .map_err(|e| anyhow::anyhow!("Failed to create OCSP CertId: {}", e))?;

        // Find the status for our certificate
        if let Some(status) = basic_response.find_status(&cert_id) {
            // Check the certificate status
            match status.status {
                openssl::ocsp::OcspCertStatus::GOOD => {
                    tracing::debug!("OCSP response: Certificate status is GOOD");
                    return Ok(RevocationStatus::Good);
                }
                openssl::ocsp::OcspCertStatus::REVOKED => {
                    tracing::warn!("OCSP response: Certificate status is REVOKED");
                    
                    // Revocation reason is available
                    tracing::warn!("Revocation reason: {:?}", status.reason);
                    
                    if let Some(revocation_time) = status.revocation_time {
                        tracing::warn!("Revocation time: {}", revocation_time);
                    }
                    
                    return Ok(RevocationStatus::Revoked);
                }
                openssl::ocsp::OcspCertStatus::UNKNOWN => {
                    tracing::debug!("OCSP response: Certificate status is UNKNOWN");
                    return Ok(RevocationStatus::Unknown);
                }
                _ => {
                    tracing::warn!("OCSP response: Unexpected certificate status");
                    return Ok(RevocationStatus::Error);
                }
            }
        }

        // No certificate status found in response for this cert_id
        tracing::warn!("OCSP response contains no status for the requested certificate");
        Ok(RevocationStatus::Unknown)
    }


    /// Check CRL revocation status
    async fn check_crl(&self, cert: &CertificateInfo, crl_url: &str) -> Result<RevocationStatus> {
        // Download CRL
        let client = reqwest::Client::builder()
            .timeout(self.check_timeout)
            .build()?;

        let response = timeout(self.check_timeout, client.get(crl_url).send()).await??;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("CRL download failed: {}", response.status()).into());
        }

        let crl_bytes = response.bytes().await?;

        // Parse CRL
        let (_, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&crl_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse CRL: {:?}", e))?;

        // Check if certificate serial number is in revoked list
        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

        let cert_serial = &parsed_cert.serial;

        // Check each revoked certificate
        for revoked_cert in crl.iter_revoked_certificates() {
            if &revoked_cert.user_certificate == cert_serial {
                return Ok(RevocationStatus::Revoked);
            }
        }

        Ok(RevocationStatus::Good)
    }

    /// Check OCSP stapling support (requires TLS connection analysis)
    pub fn check_ocsp_stapling(&self, _tls_connection: &[u8]) -> bool {
        // This would require analyzing the TLS handshake to see if
        // the server sent a Certificate Status message (type 22)
        // For now, return false as placeholder
        false
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
            der_bytes: vec![],
        };

        let result = checker.check_revocation_status(&cert, None).await.unwrap();
        assert_eq!(result.status, RevocationStatus::NotChecked);
        assert_eq!(result.method, RevocationMethod::None);
    }
}
