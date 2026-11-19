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
    let detector = crate::vulnerabilities::debian_keys::default_blacklist_populated()
        .then(crate::vulnerabilities::debian_keys::DebianKeyDetector::new);
    check_debian_weak_key_with_detector(der_bytes, detector.as_ref())
}

fn check_debian_weak_key_with_detector(
    der_bytes: &[u8],
    detector: Option<&crate::vulnerabilities::debian_keys::DebianKeyDetector>,
) -> crate::Result<Option<bool>> {
    // An empty blacklist cannot clear a certificate; report "not checked" rather
    // than a false clean verdict.
    let Some(detector) = detector else {
        return Ok(None);
    };
    let cert = OpensslX509::from_der(der_bytes)?;
    detector
        .is_weak_key(&cert)
        .map_err(debian_key_check_error)
        .map(Some)
}

fn debian_key_check_error(reason: String) -> crate::TlsError {
    crate::TlsError::CertificateError(crate::error::CertificateValidationError::InvalidChain {
        reason,
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
/// * `Ok(Some("Yes (certificate)"))` - Certificate has at least one embedded SCT
/// * `Ok(Some("No"))` - Certificate does not have embedded SCTs
/// * `Err(_)` - SCT extension is present but malformed
pub(crate) fn check_certificate_transparency(
    cert: &X509Certificate,
) -> crate::Result<Option<String>> {
    // SCT extension OID: 1.3.6.1.4.1.11129.2.4.2
    const SCT_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

    // Look for SCT extension
    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == SCT_EXTENSION_OID {
            let count = crate::certificates::ct::CtVerifier::new(false)
                .count_scts_in_extension_value(ext.value)?;
            return Ok(Some(if count > 0 {
                "Yes (certificate)".to_string()
            } else {
                "No".to_string()
            }));
        }
    }

    // No SCT extension found
    Ok(Some("No".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        certificates::revocation::cert_with_raw_extension_der,
        vulnerabilities::debian_keys::DebianKeyDetector,
    };
    use openssl::hash::{MessageDigest, hash};

    fn parsed_certificate(der: &[u8]) -> X509Certificate<'_> {
        X509Certificate::from_der(der)
            .expect("generated certificate should parse")
            .1
    }

    #[test]
    fn debian_weak_key_check_uses_the_supplied_detector() {
        let der = cert_with_raw_extension_der("2.5.29.19", b"\x05\x00").der_bytes;
        let cert = OpensslX509::from_der(&der).expect("generated certificate should parse");
        let public_key = cert
            .public_key()
            .expect("generated certificate should have a public key")
            .public_key_to_der()
            .expect("public key should serialize");
        let fingerprint = hash(MessageDigest::sha256(), &public_key)
            .expect("public key fingerprint should calculate")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let detector = DebianKeyDetector::with_hashes(vec![fingerprint]);

        assert_eq!(
            check_debian_weak_key_with_detector(&der, Some(&detector)).unwrap(),
            Some(true)
        );
        assert_eq!(
            check_debian_weak_key_with_detector(
                &der,
                Some(&DebianKeyDetector::with_hashes(vec![]))
            )
            .unwrap(),
            Some(false)
        );
        assert_eq!(
            check_debian_weak_key_with_detector(&der, None).unwrap(),
            None
        );
        assert!(check_debian_weak_key_with_detector(b"invalid", Some(&detector)).is_err());
        assert!(matches!(
            debian_key_check_error("detector failed".into()),
            crate::TlsError::CertificateError(
                crate::error::CertificateValidationError::InvalidChain { reason }
            ) if reason == "detector failed"
        ));
    }

    #[test]
    fn certificate_transparency_check_covers_absent_empty_and_present_scts() {
        let without_sct = cert_with_raw_extension_der("2.5.29.19", b"\x05\x00");
        assert_eq!(
            check_certificate_transparency(&parsed_certificate(&without_sct.der_bytes)).unwrap(),
            Some("No".to_string())
        );

        let empty_sct_list =
            cert_with_raw_extension_der("1.3.6.1.4.1.11129.2.4.2", &[0x04, 0x02, 0x00, 0x00]);
        assert_eq!(
            check_certificate_transparency(&parsed_certificate(&empty_sct_list.der_bytes)).unwrap(),
            Some("No".to_string())
        );

        let one_sct = cert_with_raw_extension_der(
            "1.3.6.1.4.1.11129.2.4.2",
            &[0x04, 0x06, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb],
        );
        assert_eq!(
            check_certificate_transparency(&parsed_certificate(&one_sct.der_bytes)).unwrap(),
            Some("Yes (certificate)".to_string())
        );

        let malformed_sct =
            cert_with_raw_extension_der("1.3.6.1.4.1.11129.2.4.2", &[0x04, 0x82, 0x00]);
        assert!(
            check_certificate_transparency(&parsed_certificate(&malformed_sct.der_bytes)).is_err()
        );
    }
}
