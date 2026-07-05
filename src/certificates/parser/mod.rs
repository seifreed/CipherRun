// Certificate Parser - Extract and parse certificate chains from TLS connections

pub mod checks;
pub mod extraction;
pub mod fingerprints;
pub mod parsing;

pub use parsing::CertificateParser;

use serde::{Deserialize, Serialize};

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub expiry_countdown: Option<String>, // Human-readable countdown to expiry (e.g., "expires in 2 months and 28 days")
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub rsa_exponent: Option<String>, // RSA public key exponent (e.g., "e 65537"), None for non-RSA keys
    pub san: Vec<String>,             // Subject Alternative Names
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub extended_validation: bool,
    pub ev_oids: Vec<String>,
    pub pin_sha256: Option<String>, // Base64-encoded SHA256 hash of public key (HPKP per RFC 7469)
    pub fingerprint_sha256: Option<String>, // SHA256 hash of entire DER-encoded certificate (colon-separated hex)
    pub debian_weak_key: Option<bool>,      // CVE-2008-0166: Debian OpenSSL weak key (legacy check)
    pub aia_url: Option<String>, // Authority Information Access URL (CA Issuers URL for intermediate cert chain)
    pub certificate_transparency: Option<String>, // Certificate Transparency status: "Yes (certificate)", "Yes (TLS extension)", "Yes (OCSP)", "No"
    pub der_bytes: Vec<u8>,
}

impl CertificateInfo {
    /// Whether this certificate is barred from signing child certificates by its
    /// keyUsage extension.
    ///
    /// RFC 5280 §4.2.1.3: when the keyUsage extension is present, the subject
    /// public key MUST NOT be used to verify signatures on certificates unless
    /// the keyCertSign bit is set. An absent keyUsage extension (an empty list
    /// here) imposes no such restriction, so it does not forbid signing.
    pub fn key_usage_forbids_cert_signing(&self) -> bool {
        !self.key_usage.is_empty()
            && !self
                .key_usage
                .iter()
                .any(|usage| usage == "Certificate Sign")
    }

    /// Whether this certificate's extendedKeyUsage bars it from TLS server
    /// authentication.
    ///
    /// RFC 5280 §4.2.1.12: when the EKU extension is present, the certificate
    /// may be used only for the listed purposes. A TLS server leaf must
    /// therefore carry id-kp-serverAuth (or anyExtendedKeyUsage). An absent EKU
    /// extension (an empty list here) imposes no restriction. Returns true when
    /// this certificate may not be used for TLS server authentication.
    pub fn eku_forbids_tls_server_auth(&self) -> bool {
        !self.extended_key_usage.is_empty()
            && !self
                .extended_key_usage
                .iter()
                .any(|usage| usage == "Server Authentication" || usage == "Any")
    }
}

/// Certificate chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    pub certificates: Vec<CertificateInfo>,
    pub chain_length: usize,
    /// Total size of certificate chain in bytes (sum of all DER-encoded certificates)
    pub chain_size_bytes: usize,
}

impl CertificateChain {
    /// Get the leaf (server) certificate
    pub fn leaf(&self) -> Option<&CertificateInfo> {
        self.certificates.first()
    }

    /// Get intermediate certificates (excludes leaf at index 0 and self-signed root at the end)
    pub fn intermediates(&self) -> &[CertificateInfo] {
        if self.certificates.len() <= 1 {
            return &[];
        }
        // If the last certificate is a self-signed root CA, exclude it
        let end = if self.is_complete() {
            self.certificates.len() - 1
        } else {
            self.certificates.len()
        };
        if end <= 1 {
            return &[];
        }
        self.certificates.get(1..end).unwrap_or(&[])
    }

    /// Check if chain is complete (has self-signed root CA)
    pub fn is_complete(&self) -> bool {
        self.certificates
            .last()
            .is_some_and(|c| c.is_ca && c.subject == c.issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_chain_helpers() {
        let leaf = CertificateInfo {
            subject: "CN=leaf".to_string(),
            is_ca: false,
            ..Default::default()
        };
        let root = CertificateInfo {
            subject: "CN=root".to_string(),
            issuer: "CN=root".to_string(),
            is_ca: true,
            ..Default::default()
        };

        let chain = CertificateChain {
            certificates: vec![leaf.clone(), root.clone()],
            chain_length: 2,
            chain_size_bytes: 0,
        };

        assert_eq!(chain.leaf().unwrap().subject, "CN=leaf");
        // [leaf, root] chain: 0 intermediates (root is excluded)
        assert_eq!(chain.intermediates().len(), 0);
        assert!(chain.is_complete());

        // Chain ending with intermediate (not self-signed) should be incomplete
        let intermediate = CertificateInfo {
            subject: "CN=intermediate".to_string(),
            issuer: "CN=root".to_string(),
            is_ca: true,
            ..Default::default()
        };
        let incomplete_chain = CertificateChain {
            certificates: vec![leaf.clone(), intermediate.clone()],
            chain_length: 2,
            chain_size_bytes: 0,
        };
        assert!(!incomplete_chain.is_complete());
        // Incomplete chain [leaf, intermediate]: 1 intermediate (no root to exclude)
        assert_eq!(incomplete_chain.intermediates().len(), 1);

        // Full chain [leaf, intermediate, root]: 1 intermediate
        let full_chain = CertificateChain {
            certificates: vec![leaf.clone(), intermediate, root.clone()],
            chain_length: 3,
            chain_size_bytes: 0,
        };
        assert!(full_chain.is_complete());
        assert_eq!(full_chain.intermediates().len(), 1);
        assert_eq!(full_chain.intermediates()[0].subject, "CN=intermediate");
    }

    #[test]
    fn test_key_usage_absent_does_not_forbid_cert_signing() {
        let cert = CertificateInfo {
            key_usage: vec![],
            ..Default::default()
        };
        assert!(!cert.key_usage_forbids_cert_signing());
    }

    #[test]
    fn test_key_usage_with_cert_sign_does_not_forbid_cert_signing() {
        let cert = CertificateInfo {
            key_usage: vec![
                "Digital Signature".to_string(),
                "Certificate Sign".to_string(),
            ],
            ..Default::default()
        };
        assert!(!cert.key_usage_forbids_cert_signing());
    }

    #[test]
    fn test_key_usage_present_without_cert_sign_forbids_cert_signing() {
        let cert = CertificateInfo {
            key_usage: vec!["Digital Signature".to_string()],
            ..Default::default()
        };
        assert!(cert.key_usage_forbids_cert_signing());
    }

    #[test]
    fn test_eku_absent_does_not_forbid_tls_server_auth() {
        let cert = CertificateInfo {
            extended_key_usage: vec![],
            ..Default::default()
        };
        assert!(!cert.eku_forbids_tls_server_auth());
    }

    #[test]
    fn test_eku_with_server_auth_does_not_forbid_tls_server_auth() {
        let cert = CertificateInfo {
            extended_key_usage: vec![
                "Server Authentication".to_string(),
                "Client Authentication".to_string(),
            ],
            ..Default::default()
        };
        assert!(!cert.eku_forbids_tls_server_auth());
    }

    #[test]
    fn test_eku_any_does_not_forbid_tls_server_auth() {
        let cert = CertificateInfo {
            extended_key_usage: vec!["Any".to_string()],
            ..Default::default()
        };
        assert!(!cert.eku_forbids_tls_server_auth());
    }

    #[test]
    fn test_eku_present_without_server_auth_forbids_tls_server_auth() {
        let cert = CertificateInfo {
            extended_key_usage: vec!["Client Authentication".to_string()],
            ..Default::default()
        };
        assert!(cert.eku_forbids_tls_server_auth());
    }
}
