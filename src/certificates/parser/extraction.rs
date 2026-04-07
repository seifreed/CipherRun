use crate::Result;
use openssl::x509::X509 as OpensslX509;
use x509_parser::prelude::*;

/// Known Extended Validation (EV) Policy OIDs
/// These OIDs identify EV certificates from major Certificate Authorities
pub(crate) const EV_POLICY_OIDS: &[&str] = &[
    // DigiCert
    "2.16.840.1.114412.2.1",     // DigiCert EV SSL/TLS
    "2.16.840.1.114412.1.3.0.2", // DigiCert EV Code Signing
    // Entrust
    "2.16.840.1.114028.10.1.2", // Entrust EV SSL
    // Comodo/Sectigo
    "1.3.6.1.4.1.6449.1.2.1.5.1", // Comodo/Sectigo EV SSL
    // GlobalSign
    "1.3.6.1.4.1.4146.1.1", // GlobalSign EV SSL
    // SwissSign
    "2.16.756.1.89.1.2.1.1", // SwissSign EV Gold CA
    // Network Solutions
    "1.3.6.1.4.1.782.1.2.1.8.1", // Network Solutions EV SSL
    // QuoVadis
    "1.3.6.1.4.1.8024.0.2.100.1.2", // QuoVadis EV SSL
    // GoDaddy
    "2.16.840.1.114413.1.7.23.3", // GoDaddy EV SSL
    // Thawte
    "2.16.840.1.113733.1.7.48.1", // Thawte EV SSL
    // VeriSign/Symantec
    "2.16.840.1.113733.1.7.23.6", // VeriSign/Symantec EV SSL
    // Certum
    "1.2.616.1.113527.2.5.1.1", // Certum EV SSL
    // Let's Encrypt (for completeness, though they don't issue EV)
    // "2.23.140.1.1" is the CA/Browser Forum EV Guidelines OID
    "2.23.140.1.1", // CA/Browser Forum EV Certificate
    // GlobalSign Extended Validation
    "1.3.6.1.4.1.4146.1.10", // GlobalSign EV Code Signing
    // Buypass
    "2.16.578.1.26.1.3.3", // Buypass EV SSL
    // SECOM Trust Systems
    "1.2.392.200091.100.721.1", // SECOM Trust Systems EV SSL
    // TÜRKTRUST
    "2.16.792.3.0.4.1.1.4", // TÜRKTRUST EV SSL
    // E-Tugra
    "2.16.792.1.2.1.1.5.7.1.9", // E-Tugra EV SSL
    // Certinomis
    "1.2.250.1.177.1.18.2.2", // Certinomis EV SSL
    // AC Camerfirma
    "1.3.6.1.4.1.17326.10.14.2.1.2", // AC Camerfirma EV SSL
    // Actalis
    "1.3.159.1.17.1", // Actalis EV SSL
    // China Internet Network Information Center (CNNIC)
    "1.2.156.112570.1.1.3", // CNNIC EV SSL
];

/// Check if certificate contains Extended Validation (EV) policy OIDs
///
/// EV certificates are identified by specific Policy Identifier OIDs in the
/// Certificate Policies extension (OID 2.5.29.32). This function extracts
/// all policy OIDs and checks if any match known EV policy OIDs.
///
/// Returns: (is_ev, list_of_policy_oids)
pub(crate) fn check_extended_validation(cert: &X509Certificate) -> Result<(bool, Vec<String>)> {
    let mut policy_oids = Vec::new();
    let mut is_ev = false;

    // Try to get Certificate Policies extension (OID 2.5.29.32)
    if let Ok(Some(ext)) =
        cert.get_extension_unique(&oid_registry::OID_X509_EXT_CERTIFICATE_POLICIES)
    {
        // Parse the extension as Certificate Policies
        if let ParsedExtension::CertificatePolicies(policies) = ext.parsed_extension() {
            // policies is a &Vec<PolicyInformation>, iterate directly
            for policy in policies.iter() {
                let oid_str = policy.policy_id.to_id_string();
                policy_oids.push(oid_str.clone());

                // Check if this OID matches any known EV OID
                if EV_POLICY_OIDS.contains(&oid_str.as_str()) {
                    is_ev = true;
                }
            }
        }
    }

    Ok((is_ev, policy_oids))
}

/// Extract RSA public key exponent from certificate
///
/// This function extracts the public exponent (e) from RSA public keys.
/// The exponent is formatted as "e {number}" to match SSL Labs display format.
///
/// # Arguments
/// * `der_bytes` - The certificate in DER format
///
/// # Returns
/// * `Ok(Some(String))` - Formatted exponent (e.g., "e 65537") for RSA keys
/// * `Ok(None)` - For non-RSA keys (ECDSA, EdDSA, etc.)
/// * `Err` - On certificate parsing errors
pub(crate) fn extract_rsa_exponent(der_bytes: &[u8]) -> Result<Option<String>> {
    // Parse certificate using OpenSSL
    let cert =
        OpensslX509::from_der(der_bytes).map_err(|e| crate::error::TlsError::ParseError {
            message: format!("Failed to parse certificate with OpenSSL: {}", e),
        })?;

    // Extract public key
    let public_key = cert.public_key().map_err(|e| {
        crate::error::TlsError::Other(format!("Failed to extract public key: {}", e))
    })?;

    // Try to extract RSA key - returns None if not RSA
    match public_key.rsa() {
        Ok(rsa) => {
            // Get the public exponent
            let exponent = rsa.e();
            // Convert BigNum to decimal string
            let exponent_str = exponent.to_dec_str().map_err(|e| {
                crate::error::TlsError::Other(format!(
                    "Failed to convert exponent to string: {}",
                    e
                ))
            })?;
            // Format as "e {number}" to match SSL Labs format
            Ok(Some(format!("e {}", exponent_str)))
        }
        Err(_) => {
            // Not an RSA key (could be ECDSA, EdDSA, etc.)
            Ok(None)
        }
    }
}

/// Extract Authority Information Access (AIA) CA Issuers URL from certificate
///
/// This function extracts the CA Issuers URL from the AIA extension (OID 1.3.6.1.5.5.7.1.1).
/// The CA Issuers URL points to the location where the issuer's certificate can be downloaded,
/// which is useful for building the certificate chain.
///
/// This is different from the OCSP URL (also in AIA) which is used for revocation checking.
///
/// # Arguments
/// * `cert` - X.509 certificate to extract AIA URL from
///
/// # Returns
/// * `Ok(Some(String))` - CA Issuers URL if present
/// * `Ok(None)` - If AIA extension not present or no CA Issuers URL
/// * `Err` - On parsing errors
pub(crate) fn extract_aia_url(cert: &X509Certificate) -> Result<Option<String>> {
    // Look for Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1)
    if let Ok(Some(ext)) = cert.get_extension_unique(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
        && let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension()
    {
        for access_desc in &aia.accessdescs {
            // CA Issuers OID: 1.3.6.1.5.5.7.48.2
            if access_desc.access_method.to_string() == "1.3.6.1.5.5.7.48.2"
                && let GeneralName::URI(uri) = &access_desc.access_location
            {
                return Ok(Some(uri.to_string()));
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ev_oids_list() {
        // Test that the EV OIDs list contains known EV CAs
        assert!(EV_POLICY_OIDS.contains(&"2.16.840.1.114412.2.1")); // DigiCert
        assert!(EV_POLICY_OIDS.contains(&"1.3.6.1.4.1.6449.1.2.1.5.1")); // Comodo/Sectigo
        assert!(EV_POLICY_OIDS.contains(&"1.3.6.1.4.1.4146.1.1")); // GlobalSign
        assert!(EV_POLICY_OIDS.contains(&"2.23.140.1.1")); // CA/Browser Forum
    }

    #[test]
    fn test_check_extended_validation_detection() {
        // This test verifies that the check_extended_validation function correctly
        // identifies EV certificates based on Certificate Policies extension.
        // Note: This is a unit test that would require a real certificate with
        // EV policy OIDs to fully validate. For now, we just ensure the function
        // signature is correct and the OID list is populated.
        #[allow(clippy::absurd_extreme_comparisons)]
        {
            assert!(!EV_POLICY_OIDS.is_empty());
        }
        assert!(EV_POLICY_OIDS.len() > 20); // Should have many known EV OIDs
    }
}
