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
/// Returns `Ok(true)` only when both DER blobs parse, the issuer public key can
/// be extracted, and the cryptographic signature check succeeds. Invalid
/// signatures return `Ok(false)`; parsing and OpenSSL verification failures are
/// returned to the caller.
pub(crate) fn verify_cert_signature(cert_der: &[u8], issuer_der: &[u8]) -> crate::Result<bool> {
    let cert = X509::from_der(cert_der)?;
    let issuer = X509::from_der(issuer_der)?;
    let issuer_pkey = issuer.public_key()?;

    Ok(cert.verify(&issuer_pkey)?)
}
