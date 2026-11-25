// Cryptographic certificate signature verification
//
// Shared helper used by trust-chain and trust-store validation to confirm that
// a certificate was genuinely signed by its claimed issuer. Name matching alone
// (subject == issuer) is not sufficient: an attacker can mint a certificate that
// names a trusted CA as issuer without holding that CA's private key.

use openssl::x509::X509;
use x509_parser::prelude::FromDer;

fn reject_trailing_der(der: &[u8], context: &str) -> crate::Result<()> {
    let (rest, _) = x509_parser::certificate::X509Certificate::from_der(der).map_err(|e| {
        crate::TlsError::ParseError {
            message: format!("Failed to parse {context}: {e:?}"),
        }
    })?;
    if !rest.is_empty() {
        return Err(crate::TlsError::ParseError {
            message: format!("{context} DER contains trailing bytes"),
        });
    }
    Ok(())
}

/// Verify that `cert_der` carries a signature produced by the private key
/// corresponding to the public key in `issuer_der`.
///
/// Returns `Ok(true)` only when both DER blobs parse, the issuer public key can
/// be extracted, and the cryptographic signature check succeeds. Invalid
/// signatures return `Ok(false)`; parsing and OpenSSL verification failures are
/// returned to the caller.
pub(crate) fn verify_cert_signature(cert_der: &[u8], issuer_der: &[u8]) -> crate::Result<bool> {
    reject_trailing_der(cert_der, "certificate")?;
    reject_trailing_der(issuer_der, "issuer certificate")?;

    let cert = X509::from_der(cert_der)?;
    let issuer = X509::from_der(issuer_der)?;
    let issuer_pkey = issuer.public_key()?;

    Ok(cert.verify(&issuer_pkey)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed_der() -> Vec<u8> {
        rcgen::generate_simple_self_signed(["example.com".to_string()])
            .expect("certificate should build")
            .cert
            .der()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn verifies_a_certificate_signed_by_the_matching_issuer() {
        let der = self_signed_der();

        assert!(verify_cert_signature(&der, &der).expect("signature verification should work"));
    }

    #[test]
    fn returns_false_when_the_issuer_key_does_not_match() {
        let cert_der = self_signed_der();
        let other_issuer_der = self_signed_der();

        assert!(
            !verify_cert_signature(&cert_der, &other_issuer_der)
                .expect("valid certificate signatures should be compared")
        );
    }

    #[test]
    fn rejects_malformed_certificate_der() {
        let issuer_der = self_signed_der();

        let error = verify_cert_signature(&[0x00], &issuer_der)
            .expect_err("malformed certificate DER should be rejected");

        assert!(error.to_string().contains("Failed to parse certificate"));
    }

    #[test]
    fn rejects_malformed_issuer_der() {
        let cert_der = self_signed_der();

        let error = verify_cert_signature(&cert_der, &[0x00])
            .expect_err("malformed issuer DER should be rejected");

        assert!(
            error
                .to_string()
                .contains("Failed to parse issuer certificate")
        );
    }

    #[test]
    fn rejects_trailing_certificate_der_bytes() {
        let cert = rcgen::generate_simple_self_signed(["example.com".to_string()])
            .expect("certificate should build");
        let mut der = cert.cert.der().as_ref().to_vec();
        der.push(0xff);

        let err = verify_cert_signature(&der, cert.cert.der().as_ref())
            .expect_err("trailing certificate DER bytes should fail");

        assert!(err.to_string().contains("trailing"));
    }

    #[test]
    fn rejects_trailing_issuer_der_bytes() {
        let cert = rcgen::generate_simple_self_signed(["example.com".to_string()])
            .expect("certificate should build");
        let mut issuer_der = cert.cert.der().as_ref().to_vec();
        issuer_der.push(0xff);

        let err = verify_cert_signature(cert.cert.der().as_ref(), &issuer_der)
            .expect_err("trailing issuer DER bytes should fail");

        assert!(err.to_string().contains("trailing"));
    }
}
