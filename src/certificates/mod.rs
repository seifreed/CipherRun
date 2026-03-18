// Certificates module - Certificate analysis and validation

pub mod advanced;
pub mod caa;
pub mod ct;
pub mod parser;
pub mod revocation;
pub mod status;
pub mod trust_stores;
pub mod validator;

// MEDIUM PRIORITY Features (11-15)
pub mod revocation_strict;

#[cfg(test)]
mod tests {
    use super::status::CertificateStatus;

    #[test]
    fn test_certificate_status_default() {
        let status = CertificateStatus::default();
        assert!(!status.is_expired);
        assert!(!status.is_self_signed);
        assert!(!status.is_mismatched);
        assert!(!status.is_revoked);
        assert!(!status.is_untrusted);
    }

    #[test]
    fn test_certificate_status_default_eq_manual() {
        let status = CertificateStatus::default();
        let manual = CertificateStatus {
            is_expired: false,
            is_self_signed: false,
            is_mismatched: false,
            is_revoked: false,
            is_untrusted: false,
        };
        assert_eq!(status.is_expired, manual.is_expired);
        assert_eq!(status.is_self_signed, manual.is_self_signed);
        assert_eq!(status.is_mismatched, manual.is_mismatched);
        assert_eq!(status.is_revoked, manual.is_revoked);
        assert_eq!(status.is_untrusted, manual.is_untrusted);
    }
}
