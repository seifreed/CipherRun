use super::CertificateInfo;

pub(crate) fn base_cert(not_before: String, not_after: String) -> CertificateInfo {
    CertificateInfo {
        subject: "CN=example.com".to_string(),
        issuer: "CN=CA".to_string(),
        serial_number: "123".to_string(),
        not_before,
        not_after,
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key_algorithm: "rsaEncryption".to_string(),
        public_key_size: Some(2048),
        san: vec!["example.com".to_string()],
        ..Default::default()
    }
}
