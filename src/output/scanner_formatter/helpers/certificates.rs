use crate::certificates::revocation::RevocationStatus;
use colored::{ColoredString, Colorize};

/// Color a public-key size by strength, using algorithm-appropriate thresholds.
///
/// Elliptic-curve keys are far smaller than RSA/DSA keys for equivalent
/// strength, so a flat 2048-bit floor wrongly paints strong EC keys (P-256,
/// P-384, Ed25519) red. The weak floor mirrors the certificate key-strength
/// validator: 224 bits for EC, 2048 bits for RSA/DSA.
pub(crate) fn format_key_size(key_size: usize, public_key_algorithm: &str) -> ColoredString {
    let alg = public_key_algorithm.to_lowercase();
    let is_ec = alg.starts_with("ec")
        || alg.contains("ecpublickey")
        || alg.contains("ecdsa")
        || alg.contains("ed25519")
        || alg.contains("ed448");

    let weak_below = if is_ec { 224 } else { 2048 };

    let text = key_size.to_string();
    if key_size < weak_below {
        text.red()
    } else {
        text.green()
    }
}

pub(crate) fn format_revocation_status(status: &RevocationStatus) -> ColoredString {
    match status {
        RevocationStatus::Good => "Y Not Revoked".green(),
        RevocationStatus::Revoked => "X REVOKED".red().bold(),
        RevocationStatus::Unknown => "? Unknown".yellow(),
        RevocationStatus::Error => "X Check Failed".red(),
        RevocationStatus::NotChecked => "- Not Checked".normal(),
    }
}

pub(crate) fn get_cert_type(index: usize, chain_length: usize) -> &'static str {
    match index {
        0 => "Leaf Certificate",
        n if n == chain_length - 1 && chain_length > 2 => "Root/Top CA",
        n if n == chain_length - 1 => "Issuer CA",
        _ => "Intermediate CA",
    }
}
