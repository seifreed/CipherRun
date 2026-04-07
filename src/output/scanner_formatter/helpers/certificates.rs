use colored::*;

use crate::certificates::revocation::RevocationStatus;

pub(crate) fn format_key_size(key_size: usize) -> ColoredString {
    if key_size >= 2048 {
        key_size.to_string().green()
    } else {
        key_size.to_string().red()
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
