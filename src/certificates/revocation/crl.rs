use super::{RevocationChecker, RevocationStatus, parse_x509_der_exact};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use tokio::time::timeout;
use x509_parser::prelude::*;
use x509_parser::revocation_list::CertificateRevocationList;

fn parse_crl_der_exact(der: &[u8]) -> Result<CertificateRevocationList<'_>> {
    let (rest, crl) = CertificateRevocationList::from_der(der).map_err(|e| {
        crate::error::TlsError::ParseError {
            message: format!("Failed to parse CRL: {:?}", e),
        }
    })?;
    if !rest.is_empty() {
        return Err(crate::error::TlsError::ParseError {
            message: format!("CRL DER contains {} trailing byte(s)", rest.len()),
        });
    }
    Ok(crl)
}

fn is_http_crl_url(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

impl RevocationChecker {
    /// Extract CRL distribution point URL from certificate
    pub(crate) fn extract_crl_url(&self, cert: &CertificateInfo) -> Result<Option<String>> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(None);
        }

        let parsed_cert = parse_x509_der_exact(&cert.der_bytes, "certificate")?;

        // Look for CRL Distribution Points extension
        if let Some(ext) = parsed_cert
            .get_extension_unique(&oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
            .map_err(|error| crate::TlsError::ParseError {
                message: format!("Failed to parse CRL Distribution Points extension: {error}"),
            })?
        {
            match ext.parsed_extension() {
                ParsedExtension::CRLDistributionPoints(crl_dp) => {
                    for point in &crl_dp.points {
                        if let Some(dist_point) = &point.distribution_point
                            && let x509_parser::extensions::DistributionPointName::FullName(names) =
                                dist_point
                        {
                            for name in names {
                                if let GeneralName::URI(uri) = name
                                    && is_http_crl_url(uri)
                                {
                                    return Ok(Some(uri.to_string()));
                                }
                            }
                        }
                    }
                }
                other => {
                    return Err(crate::TlsError::ParseError {
                        message: format!(
                            "Failed to parse CRL Distribution Points extension: {other:?}"
                        ),
                    });
                }
            }
        }

        Ok(None)
    }

    /// Check CRL revocation status
    pub(crate) async fn check_crl(
        &self,
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
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

        // Cap the body: the CRL distribution point URL comes from the (untrusted)
        // certificate being scanned, so an unbounded read is an OOM vector. Large
        // CAs publish multi-MB CRLs, so the limit is generous but finite.
        const MAX_CRL_BYTES: u64 = 64 * 1024 * 1024;
        let crl_bytes =
            crate::utils::http::read_response_body_capped(response, MAX_CRL_BYTES, "CRL").await?;

        // Parse CRL
        let crl = parse_crl_der_exact(&crl_bytes)?;

        // SECURITY: verify the CRL signature against the issuing CA before trusting
        // its revoked-serial list. Over the plain-HTTP CRL distribution point a
        // forged/MITM'd CRL could omit a revoked serial and yield a false "Good".
        let issuer = issuer.ok_or_else(|| {
            crate::error::TlsError::Other(
                "Issuer certificate required to verify CRL signature".into(),
            )
        })?;
        let issuer_cert = parse_x509_der_exact(&issuer.der_bytes, "issuer certificate")?;
        if crl.verify_signature(issuer_cert.public_key()).is_err() {
            tracing::warn!(
                "CRL signature verification failed for {}; not trusting it",
                crl_url
            );
            return Err(crate::error::TlsError::Other(
                "CRL signature verification failed".into(),
            ));
        }

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
        let parsed_cert = parse_x509_der_exact(&cert.der_bytes, "certificate")?;

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

    fn cert_with_raw_extension_der(oid: &str, contents: &[u8]) -> CertificateInfo {
        use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::hash::MessageDigest as OpensslMessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "malformed-extension.example.com")
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
        let oid = Asn1Object::from_str(oid).unwrap();
        let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
        let extension = X509Extension::new_from_der(&oid, false, &contents).unwrap();
        builder.append_extension(extension).unwrap();
        builder.sign(&pkey, OpensslMessageDigest::sha256()).unwrap();

        CertificateInfo {
            der_bytes: builder.build().to_der().unwrap(),
            ..Default::default()
        }
    }

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

    #[test]
    fn test_extract_crl_url_malformed_distribution_points_returns_error() {
        let checker = RevocationChecker::new(false);
        let cert = cert_with_raw_extension_der("2.5.29.31", b"\x05\x00");

        let err = checker.extract_crl_url(&cert).unwrap_err();
        assert!(format!("{err}").contains("CRL Distribution Points extension"));
    }

    #[test]
    fn test_is_http_crl_url_rejects_http_prefix_schemes() {
        assert!(is_http_crl_url("http://example.com/root.crl"));
        assert!(is_http_crl_url("https://example.com/root.crl"));
        assert!(is_http_crl_url("HTTP://example.com/root.crl"));
        assert!(is_http_crl_url("HTTPS://example.com/root.crl"));
        assert!(!is_http_crl_url("httpx://example.com/root.crl"));
        assert!(!is_http_crl_url("ftp://example.com/root.crl"));
        assert!(!is_http_crl_url("http://"));
    }

    #[test]
    fn test_parse_crl_der_exact_rejects_trailing_bytes() {
        let mut crl = vec![
            0x30, 0x35, 0x30, 0x20, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x00, 0x17, 0x0d, b'2', b'5', b'0', b'1', b'0',
            b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x02, 0x00, 0x00,
        ];
        assert!(parse_crl_der_exact(&crl).is_ok());

        crl.push(0x00);
        let err = parse_crl_der_exact(&crl).expect_err("trailing CRL bytes should fail");
        assert!(format!("{err}").contains("trailing byte"));
    }
}
