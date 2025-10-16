// Certificate Parser - Extract and parse certificate chains from TLS connections

use crate::Result;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use x509_parser::prelude::*;

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub san: Vec<String>, // Subject Alternative Names
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub der_bytes: Vec<u8>,
}

/// Certificate chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    pub certificates: Vec<CertificateInfo>,
    pub chain_length: usize,
}

/// Certificate parser
pub struct CertificateParser {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    mtls_config: Option<MtlsConfig>,
}

impl CertificateParser {
    /// Create new certificate parser
    pub fn new(target: Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            mtls_config: None,
        }
    }

    /// Create new certificate parser with mTLS configuration
    pub fn with_mtls(target: Target, mtls_config: MtlsConfig) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            mtls_config: Some(mtls_config),
        }
    }

    /// Get certificate chain from server
    pub async fn get_certificate_chain(&self) -> Result<CertificateChain> {
        // Use rustls to get the certificate chain
        use rustls::{ClientConfig, RootCertStore};
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        let addr = self.target.socket_addrs()[0];

        // Connect TCP
        let stream = timeout(self.connect_timeout, TcpStream::connect(addr)).await??;

        // Build TLS connector with or without client auth
        let connector = if let Some(ref mtls_config) = self.mtls_config {
            // Use mTLS configuration
            mtls_config.build_tls_connector()?
        } else {
            // Standard TLS without client auth
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            TlsConnector::from(Arc::new(config))
        };

        // Connect with TLS
        let hostname = self.target.hostname.clone();
        let domain = rustls_pki_types::ServerName::try_from(hostname.as_str())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        let tls_stream = timeout(self.read_timeout, connector.connect(domain, stream)).await??;

        // Get peer certificates
        let (_io, connection) = tls_stream.into_inner();
        let peer_certificates = connection.peer_certificates();

        if peer_certificates.is_none() {
            anyhow::bail!("No certificates received from server");
        }

        let certs = peer_certificates.unwrap();
        let mut parsed_certs = Vec::new();

        for cert_der in certs {
            let cert_info = Self::parse_certificate(cert_der)?;
            parsed_certs.push(cert_info);
        }

        Ok(CertificateChain {
            chain_length: parsed_certs.len(),
            certificates: parsed_certs,
        })
    }

    /// Parse a single certificate from DER bytes
    pub fn parse_certificate(der_bytes: &[u8]) -> Result<CertificateInfo> {
        let (_, cert) = X509Certificate::from_der(der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

        // Extract Subject Alternative Names
        let mut san = Vec::new();
        if let Ok(Some(ext)) =
            cert.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            && let ParsedExtension::SubjectAlternativeName(san_gen) = ext.parsed_extension()
        {
            for name in &san_gen.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        san.push(dns.to_string());
                    }
                    GeneralName::IPAddress(ip) => {
                        san.push(format!("IP:{}", hex::encode(ip)));
                    }
                    _ => {}
                }
            }
        }

        // Extract Key Usage
        let mut key_usage = Vec::new();
        if let Ok(Some(ext)) = cert.get_extension_unique(&oid_registry::OID_X509_EXT_KEY_USAGE)
            && let ParsedExtension::KeyUsage(ku) = ext.parsed_extension()
        {
            if ku.digital_signature() {
                key_usage.push("Digital Signature".to_string());
            }
            if ku.key_encipherment() {
                key_usage.push("Key Encipherment".to_string());
            }
            if ku.key_cert_sign() {
                key_usage.push("Certificate Sign".to_string());
            }
        }

        // Extract Extended Key Usage
        let mut extended_key_usage = Vec::new();
        if let Ok(Some(ext)) =
            cert.get_extension_unique(&oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE)
            && let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension()
        {
            for oid in eku.other.iter() {
                let usage = match oid.to_string().as_str() {
                    "1.3.6.1.5.5.7.3.1" => "Server Authentication",
                    "1.3.6.1.5.5.7.3.2" => "Client Authentication",
                    "1.3.6.1.5.5.7.3.3" => "Code Signing",
                    "1.3.6.1.5.5.7.3.4" => "Email Protection",
                    _ => "Unknown",
                };
                extended_key_usage.push(usage.to_string());
            }
            // Also check the specific boolean flags
            if eku.server_auth && !extended_key_usage.contains(&"Server Authentication".to_string())
            {
                extended_key_usage.push("Server Authentication".to_string());
            }
            if eku.client_auth && !extended_key_usage.contains(&"Client Authentication".to_string())
            {
                extended_key_usage.push("Client Authentication".to_string());
            }
        }

        // Check if CA certificate
        let is_ca = cert
            .basic_constraints()
            .map(|bc| bc.map(|ext| ext.value.ca).unwrap_or(false))
            .unwrap_or(false);

        // Get public key size (key_size() returns size in bits for RSA modulus)
        let public_key_size = match cert.public_key().parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => Some(rsa.key_size()),
            Ok(x509_parser::public_key::PublicKey::EC(ec)) => Some(ec.key_size()),
            _ => None,
        };

        Ok(CertificateInfo {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            serial_number: format!("{:x}", cert.serial),
            not_before: cert.validity().not_before.to_string(),
            not_after: cert.validity().not_after.to_string(),
            signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
            public_key_algorithm: cert.public_key().algorithm.algorithm.to_string(),
            public_key_size,
            san,
            is_ca,
            key_usage,
            extended_key_usage,
            der_bytes: der_bytes.to_vec(),
        })
    }

    /// Get leaf certificate (first in chain)
    pub async fn get_leaf_certificate(&self) -> Result<CertificateInfo> {
        let chain = self.get_certificate_chain().await?;
        chain
            .certificates
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No certificates in chain"))
    }
}

impl CertificateChain {
    /// Get the leaf (server) certificate
    pub fn leaf(&self) -> Option<&CertificateInfo> {
        self.certificates.first()
    }

    /// Get intermediate certificates
    pub fn intermediates(&self) -> &[CertificateInfo] {
        if self.certificates.len() > 1 {
            &self.certificates[1..]
        } else {
            &[]
        }
    }

    /// Check if chain is complete (has root CA)
    pub fn is_complete(&self) -> bool {
        self.certificates.last().map(|c| c.is_ca).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_get_certificate_chain() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let parser = CertificateParser::new(target);

        let chain = parser.get_certificate_chain().await.unwrap();

        assert!(chain.chain_length > 0);
        assert!(!chain.certificates.is_empty());

        let leaf = chain.leaf().unwrap();
        assert!(!leaf.subject.is_empty());
        assert!(!leaf.san.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_get_leaf_certificate() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let parser = CertificateParser::new(target);

        let cert = parser.get_leaf_certificate().await.unwrap();

        assert!(!cert.subject.is_empty());
        assert!(!cert.issuer.is_empty());
        assert!(cert.public_key_size.is_some());
    }
}
