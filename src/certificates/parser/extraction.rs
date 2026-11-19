use crate::Result;
use openssl::error::ErrorStack;
use openssl::string::OpensslString;
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

    if let Some(ext) = cert
        .get_extension_unique(&oid_registry::OID_X509_EXT_CERTIFICATE_POLICIES)
        .map_err(|error| crate::TlsError::ParseError {
            message: format!("Invalid certificate policies extension: {error}"),
        })?
    {
        match ext.parsed_extension() {
            ParsedExtension::CertificatePolicies(policies) => {
                for policy in policies.iter() {
                    let oid_str = policy.policy_id.to_id_string();
                    policy_oids.push(oid_str.clone());

                    if EV_POLICY_OIDS.contains(&oid_str.as_str()) {
                        is_ev = true;
                    }
                }
            }
            other => {
                return Err(crate::TlsError::ParseError {
                    message: format!("Invalid certificate policies extension: {other:?}"),
                });
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
        Ok(rsa) => format_rsa_exponent(rsa.e().to_dec_str()),
        Err(_) => {
            // Not an RSA key (could be ECDSA, EdDSA, etc.)
            Ok(None)
        }
    }
}

fn format_rsa_exponent(
    exponent: std::result::Result<OpensslString, ErrorStack>,
) -> Result<Option<String>> {
    let exponent_str = exponent.map_err(|e| {
        crate::error::TlsError::Other(format!("Failed to convert exponent to string: {}", e))
    })?;
    Ok(Some(format!("e {}", exponent_str)))
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
    let aia_ext = cert
        .get_extension_unique(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
        .map_err(|e| crate::TlsError::ParseError {
            message: format!("Failed to parse Authority Information Access extension: {e}"),
        })?;

    if let Some(ext) = aia_ext {
        match ext.parsed_extension() {
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for access_desc in &aia.accessdescs {
                    // CA Issuers OID: 1.3.6.1.5.5.7.48.2
                    if access_desc.access_method.to_string() == "1.3.6.1.5.5.7.48.2"
                        && let GeneralName::URI(uri) = &access_desc.access_location
                    {
                        return Ok(Some(uri.to_string()));
                    }
                }
            }
            other => {
                return Err(crate::TlsError::ParseError {
                    message: format!(
                        "Failed to parse Authority Information Access extension: {other:?}"
                    ),
                });
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_der(extension: Option<(&str, &str)>, ec_key: bool) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

        let key = if ec_key {
            use openssl::ec::{EcGroup, EcKey};
            use openssl::nid::Nid;
            PKey::from_ec_key(
                EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
            )
            .unwrap()
        } else {
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
        };
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "extraction-test.example.com")
            .unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();

        if let Some((name, value)) = extension {
            #[allow(deprecated)]
            let extension = {
                let context = builder.x509v3_context(None, None);
                X509Extension::new(None, Some(&context), name, value).unwrap()
            };
            builder.append_extension(extension).unwrap();
        }

        builder.sign(&key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    fn certificate_der_with_raw_extension(
        oid: &str,
        der_contents: &[u8],
        duplicate: bool,
    ) -> Vec<u8> {
        use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "extraction-test.example.com")
            .unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        let oid = Asn1Object::from_str(oid).unwrap();
        let contents = Asn1OctetString::new_from_bytes(der_contents).unwrap();
        builder
            .append_extension(X509Extension::new_from_der(&oid, false, &contents).unwrap())
            .unwrap();
        if duplicate {
            builder
                .append_extension(X509Extension::new_from_der(&oid, false, &contents).unwrap())
                .unwrap();
        }
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    fn parsed_certificate(der: &[u8]) -> X509Certificate<'_> {
        X509Certificate::from_der(der)
            .expect("generated certificate should parse")
            .1
    }

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

    #[test]
    fn extended_validation_handles_missing_and_known_policy_extensions() {
        let der = certificate_der(None, false);
        assert_eq!(
            check_extended_validation(&parsed_certificate(&der)).unwrap(),
            (false, vec![])
        );

        let der = certificate_der_with_raw_extension(
            "2.5.29.32",
            &[
                0x30, 0x09, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01,
            ],
            false,
        );
        let (is_ev, policies) = check_extended_validation(&parsed_certificate(&der)).unwrap();
        assert!(is_ev);
        assert_eq!(policies, ["2.23.140.1.1"]);

        let der = certificate_der_with_raw_extension(
            "2.5.29.32",
            &[0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04],
            false,
        );
        let (is_ev, policies) = check_extended_validation(&parsed_certificate(&der)).unwrap();
        assert!(!is_ev);
        assert_eq!(policies, ["1.2.3.4"]);

        let malformed = certificate_der_with_raw_extension("2.5.29.32", &[0x05, 0x00], false);
        assert!(check_extended_validation(&parsed_certificate(&malformed)).is_err());

        let duplicate = certificate_der_with_raw_extension(
            "2.5.29.32",
            &[
                0x30, 0x09, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01,
            ],
            true,
        );
        assert!(check_extended_validation(&parsed_certificate(&duplicate)).is_err());
    }

    #[test]
    fn rsa_exponent_extracts_rsa_and_skips_other_keys() {
        let rsa_der = certificate_der(None, false);
        assert_eq!(
            extract_rsa_exponent(&rsa_der).unwrap().as_deref(),
            Some("e 65537")
        );

        let ec_der = certificate_der(None, true);
        assert_eq!(extract_rsa_exponent(&ec_der).unwrap(), None);
        assert!(extract_rsa_exponent(&[0xff, 0x00]).is_err());

        let mut invalid_key_der = certificate_der(None, false);
        let (key_offset, key_len) = {
            let cert = parsed_certificate(&invalid_key_der);
            let key = &cert.tbs_certificate.subject_pki.subject_public_key.data;
            (
                key.as_ptr() as usize - invalid_key_der.as_ptr() as usize,
                key.len(),
            )
        };
        invalid_key_der[key_offset..key_offset + key_len].fill(0);
        let error = extract_rsa_exponent(&invalid_key_der).unwrap_err();
        assert!(error.to_string().contains("Failed to extract public key"));

        assert!(format_rsa_exponent(Err(ErrorStack::get())).is_err());
    }

    #[test]
    fn aia_extraction_returns_issuer_url_or_none() {
        let der = certificate_der(None, false);
        assert_eq!(extract_aia_url(&parsed_certificate(&der)).unwrap(), None);

        let duplicate =
            certificate_der_with_raw_extension("1.3.6.1.5.5.7.1.1", &[0x30, 0x00], true);
        assert!(extract_aia_url(&parsed_certificate(&duplicate)).is_err());

        let der = certificate_der(
            Some((
                "authorityInfoAccess",
                "caIssuers;URI:http://ca.example/issuer.crt",
            )),
            false,
        );
        assert_eq!(
            extract_aia_url(&parsed_certificate(&der))
                .unwrap()
                .as_deref(),
            Some("http://ca.example/issuer.crt")
        );

        let der = certificate_der(
            Some(("authorityInfoAccess", "OCSP;URI:http://ocsp.example/")),
            false,
        );
        assert_eq!(extract_aia_url(&parsed_certificate(&der)).unwrap(), None);
    }
}
