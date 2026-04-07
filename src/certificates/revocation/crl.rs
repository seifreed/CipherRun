use super::{RevocationChecker, RevocationStatus};
use crate::certificates::parser::CertificateInfo;
use crate::Result;
use tokio::time::timeout;
use x509_parser::prelude::*;

impl RevocationChecker {
    /// Extract CRL distribution point URL from certificate
    pub(crate) fn extract_crl_url(&self, cert: &CertificateInfo) -> Result<Option<String>> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(None);
        }

        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse certificate: {:?}", e),
            }
        })?;

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

    /// Check CRL revocation status
    pub(crate) async fn check_crl(
        &self,
        cert: &CertificateInfo,
        crl_url: &str,
    ) -> Result<RevocationStatus> {
        // Download CRL
        let client = reqwest::Client::builder()
            .timeout(self.check_timeout)
            .build()?;

        let response = timeout(self.check_timeout, client.get(crl_url).send()).await??;

        if !response.status().is_success() {
            return Err(crate::error::TlsError::Other(format!(
                "CRL download failed: {}",
                response.status()
            )));
        }

        let crl_bytes = response.bytes().await?;

        // Parse CRL
        let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(
            &crl_bytes,
        )
        .map_err(|e| crate::error::TlsError::ParseError {
            message: format!("Failed to parse CRL: {:?}", e),
        })?;

        // Validate CRL is not expired (check nextUpdate)
        if let Some(next_update) = crl.next_update() {
            let now = ASN1Time::now();
            if now > next_update {
                tracing::warn!(
                    "CRL from {} has expired (nextUpdate: {:?})",
                    crl_url,
                    next_update
                );
                return Err(crate::error::TlsError::Other(format!(
                    "CRL has expired (nextUpdate: {:?})",
                    next_update
                )));
            }
        }

        // Check if certificate serial number is in revoked list
        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse certificate: {:?}", e),
            }
        })?;

        let cert_serial = &parsed_cert.serial;

        // Check each revoked certificate
        for revoked_cert in crl.iter_revoked_certificates() {
            if &revoked_cert.user_certificate == cert_serial {
                return Ok(RevocationStatus::Revoked);
            }
        }

        Ok(RevocationStatus::Good)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_crl_url_empty_der() {
        let checker = RevocationChecker::new(true);
        let cert = CertificateInfo {
            der_bytes: vec![],
            ..Default::default()
        };

        assert!(checker.extract_crl_url(&cert).unwrap().is_none());
    }

    #[test]
    fn test_extract_crl_url_invalid_der_returns_error() {
        let checker = RevocationChecker::new(false);
        let cert = CertificateInfo {
            der_bytes: vec![0x01, 0x02, 0x03],
            ..Default::default()
        };

        let err = checker.extract_crl_url(&cert).unwrap_err();
        assert!(format!("{err}").contains("Failed to parse certificate"));
    }
}
