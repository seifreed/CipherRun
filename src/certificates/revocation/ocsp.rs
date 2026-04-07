use super::{RevocationChecker, RevocationStatus};
use crate::certificates::parser::CertificateInfo;
use crate::Result;
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspRequest, OcspResponse, OcspResponseStatus};
use openssl::x509::X509;
use tokio::time::timeout;
use x509_parser::prelude::*;

impl RevocationChecker {
    /// Extract OCSP responder URL from certificate
    pub(crate) fn extract_ocsp_url(&self, cert: &CertificateInfo) -> Result<Option<String>> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(None);
        }

        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse certificate: {:?}", e),
            }
        })?;

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

    /// Check OCSP revocation status
    pub(crate) async fn check_ocsp(
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

        // Handle timeout separately from HTTP errors
        // This allows callers to distinguish between:
        // - Timeout: might want to retry or fall back to CRL
        // - HTTP error: might indicate server issue, should fall back to CRL
        let response = match timeout(
            self.check_timeout,
            client
                .post(ocsp_url)
                .header("Content-Type", "application/ocsp-request")
                .body(request_body)
                .send(),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(http_err)) => {
                // HTTP error (connection failed, DNS resolution, etc.)
                // Return Err to allow caller to fall back to CRL
                tracing::warn!(
                    "OCSP HTTP request failed for {}: {}",
                    cert.subject,
                    http_err
                );
                return Err(crate::error::TlsError::Other(format!(
                    "OCSP HTTP request failed: {}",
                    http_err
                )));
            }
            Err(_) => {
                // Timeout occurred - OCSP server might be slow
                // Log and return Unknown status - caller may want to retry or use CRL
                tracing::warn!(
                    "OCSP request timed out for {} after {:?}",
                    cert.subject,
                    self.check_timeout
                );
                return Err(crate::error::TlsError::Timeout {
                    duration: self.check_timeout,
                });
            }
        };

        if !response.status().is_success() {
            return Err(crate::error::TlsError::Other(format!(
                "OCSP responder returned error: {}",
                response.status()
            )));
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
            crate::error::TlsError::Other("Issuer certificate required for OCSP request".into())
        })?;

        // Parse certificates from DER bytes using OpenSSL
        let cert_x509 =
            X509::from_der(&cert.der_bytes).map_err(|e| crate::error::TlsError::ParseError {
                message: format!("Failed to parse certificate DER: {}", e),
            })?;

        let issuer_x509 = X509::from_der(&issuer_info.der_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse issuer certificate DER: {}", e),
            }
        })?;

        // Create OCSP certificate ID
        // This combines the certificate serial number with hashes of the issuer's name and public key
        let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), &cert_x509, &issuer_x509)
            .map_err(|e| {
                crate::error::TlsError::Other(format!("Failed to create OCSP CertId: {}", e))
            })?;

        // Build OCSP request
        let mut ocsp_req = OcspRequest::new().map_err(|e| {
            crate::error::TlsError::Other(format!("Failed to create OCSP request: {}", e))
        })?;

        ocsp_req.add_id(cert_id).map_err(|e| {
            crate::error::TlsError::Other(format!("Failed to add CertId to OCSP request: {}", e))
        })?;

        // Note: Nonce is not added because some OCSP responders don't support it
        let request_der = ocsp_req.to_der().map_err(|e| {
            crate::error::TlsError::Other(format!("Failed to serialize OCSP request to DER: {}", e))
        })?;

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
        let ocsp_response = OcspResponse::from_der(response_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse OCSP response: {}", e),
            }
        })?;

        // Check the response status
        let response_status = ocsp_response.status();

        match response_status {
            OcspResponseStatus::SUCCESSFUL => {
                // Response is successful, extract the basic response
            }
            OcspResponseStatus::MALFORMED_REQUEST => {
                return Err(crate::error::TlsError::Other(
                    "OCSP responder reported malformed request".into(),
                ));
            }
            OcspResponseStatus::INTERNAL_ERROR => {
                return Err(crate::error::TlsError::Other(
                    "OCSP responder reported internal error".into(),
                ));
            }
            OcspResponseStatus::TRY_LATER => {
                return Err(crate::error::TlsError::Other(
                    "OCSP responder is temporarily unavailable".into(),
                ));
            }
            OcspResponseStatus::SIG_REQUIRED => {
                return Err(crate::error::TlsError::Other(
                    "OCSP responder requires signed request".into(),
                ));
            }
            OcspResponseStatus::UNAUTHORIZED => {
                return Err(crate::error::TlsError::Other(
                    "OCSP responder reported unauthorized request".into(),
                ));
            }
            _ => {
                return Err(crate::error::TlsError::Other(format!(
                    "OCSP responder returned unknown status: {:?}",
                    response_status
                )));
            }
        }

        // Get the basic response from the OCSP response
        let basic_response = ocsp_response.basic().map_err(|e| {
            crate::error::TlsError::Other(format!("Failed to get basic OCSP response: {}", e))
        })?;

        // Recreate the certificate ID to look up the status
        let issuer_info = issuer.ok_or_else(|| {
            crate::error::TlsError::Other(
                "Issuer certificate required for OCSP response parsing".into(),
            )
        })?;

        let cert_x509 =
            X509::from_der(&cert.der_bytes).map_err(|e| crate::error::TlsError::ParseError {
                message: format!("Failed to parse certificate DER: {}", e),
            })?;

        let issuer_x509 = X509::from_der(&issuer_info.der_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse issuer certificate DER: {}", e),
            }
        })?;

        let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), &cert_x509, &issuer_x509)
            .map_err(|e| {
                crate::error::TlsError::Other(format!("Failed to create OCSP CertId: {}", e))
            })?;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_urls_empty_der() {
        let checker = RevocationChecker::new(true);
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            expiry_countdown: None,
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

        assert!(checker.extract_ocsp_url(&cert).unwrap().is_none());
    }

    #[test]
    fn test_extract_ocsp_url_invalid_der_returns_error() {
        let checker = RevocationChecker::new(false);
        let cert = CertificateInfo {
            der_bytes: vec![0x01, 0x02, 0x03],
            ..Default::default()
        };

        let err = checker.extract_ocsp_url(&cert).unwrap_err();
        assert!(format!("{err}").contains("Failed to parse certificate"));
    }
}
