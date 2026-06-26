use openssl::x509::X509 as OpensslX509;
use x509_parser::prelude::*;

/// Check if certificate uses a Debian weak key (CVE-2008-0166)
///
/// This function checks the certificate against the Debian weak key database.
///
/// # Arguments
/// * `der_bytes` - DER-encoded certificate
///
/// # Returns
/// * `Some(true)` - Certificate uses a known Debian weak key
/// * `Some(false)` - Certificate does not use a weak key
/// * `None` - Not checked (blacklist not populated)
pub(crate) fn check_debian_weak_key(der_bytes: &[u8]) -> crate::Result<Option<bool>> {
    // An empty blacklist cannot clear a certificate; report "not checked" rather
    // than a false clean verdict.
    if !crate::vulnerabilities::debian_keys::default_blacklist_populated() {
        return Ok(None);
    }
    let cert = OpensslX509::from_der(der_bytes)?;
    crate::vulnerabilities::debian_keys::is_debian_weak_key(&cert)
        .map(Some)
        .map_err(|reason| {
            crate::TlsError::CertificateError(
                crate::error::CertificateValidationError::InvalidChain { reason },
            )
        })
}

/// Check for Certificate Transparency (CT) SCT extension in certificate
///
/// This function checks if the certificate contains Signed Certificate Timestamps (SCTs)
/// embedded in the X.509 extension with OID 1.3.6.1.4.1.11129.2.4.2.
///
/// # Arguments
/// * `cert` - X.509 certificate to check
///
/// # Returns
/// * `Some("Yes (certificate)")` - Certificate has SCT extension
/// * `Some("No")` - Certificate does not have SCT extension
/// * `None` - Unable to check (parsing error)
pub(crate) fn check_certificate_transparency(cert: &X509Certificate) -> Option<String> {
    // SCT extension OID: 1.3.6.1.4.1.11129.2.4.2
    const SCT_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

    // Look for SCT extension
    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == SCT_EXTENSION_OID {
            // SCT extension found - certificate contains embedded SCTs
            return Some("Yes (certificate)".to_string());
        }
    }

    // No SCT extension found
    Some("No".to_string())
}
