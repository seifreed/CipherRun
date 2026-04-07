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
        &self.certificates[1..end]
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
}
