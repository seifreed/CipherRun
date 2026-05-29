// Cryptographic certificate signature verification
//
// Shared helper used by trust-chain and trust-store validation to confirm that
// a certificate was genuinely signed by its claimed issuer. Name matching alone
// (subject == issuer) is not sufficient: an attacker can mint a certificate that
// names a trusted CA as issuer without holding that CA's private key.

use openssl::x509::X509;

/// Verify that `cert_der` carries a signature produced by the private key
/// corresponding to the public key in `issuer_der`.
///
/// Returns `true` only when both DER blobs parse, the issuer public key can be
/// extracted, and the cryptographic signature check succeeds. Any parsing or
/// verification failure returns `false`.
pub(crate) fn verify_cert_signature(cert_der: &[u8], issuer_der: &[u8]) -> bool {
    let cert = match X509::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!("Failed to parse certificate DER bytes for signature verification");
            return false;
        }
    };

    let issuer = match X509::from_der(issuer_der) {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!(
                "Failed to parse issuer certificate DER bytes for signature verification"
            );
            return false;
        }
    };

    let issuer_pkey = match issuer.public_key() {
        Ok(pk) => pk,
        Err(_) => {
            tracing::debug!("Failed to extract issuer public key for signature verification");
            return false;
        }
    };

    cert.verify(&issuer_pkey).unwrap_or(false)
}
