use crate::Result;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::time::timeout;
use x509_parser::prelude::*;

use super::{CertificateChain, CertificateInfo};

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
        let stream =
            crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None).await?;

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
            .map_err(|_| crate::error::TlsError::ParseError {
                message: "Invalid DNS name".into(),
            })?
            .to_owned();

        let tls_stream = timeout(self.read_timeout, connector.connect(domain, stream)).await??;

        // Get peer certificates
        let (_io, connection) = tls_stream.into_inner();
        let peer_certificates = connection.peer_certificates();

        if peer_certificates.is_none() {
            return Err(crate::error::TlsError::Other(
                "No certificates received from server".into(),
            ));
        }

        let certs = peer_certificates.ok_or_else(|| {
            crate::error::TlsError::Other("No certificates received from server".into())
        })?;

        // Limit certificate chain size to prevent DoS
        const MAX_CERT_CHAIN_LENGTH: usize = 100;
        if certs.len() > MAX_CERT_CHAIN_LENGTH {
            tracing::warn!(
                "Certificate chain too long ({} certs), truncating to {}",
                certs.len(),
                MAX_CERT_CHAIN_LENGTH
            );
        }

        let certs_to_process = certs.iter().take(MAX_CERT_CHAIN_LENGTH);
        let mut parsed_certs = Vec::new();

        for cert_der in certs_to_process {
            let cert_info = Self::parse_certificate(cert_der)?;
            parsed_certs.push(cert_info);
        }

        // Calculate total chain size in bytes (sum of all DER-encoded certificate sizes)
        let chain_size_bytes: usize = parsed_certs.iter().map(|c| c.der_bytes.len()).sum();

        Ok(CertificateChain {
            chain_length: parsed_certs.len(),
            chain_size_bytes,
            certificates: parsed_certs,
        })
    }

    /// Parse a single certificate from DER bytes
    pub fn parse_certificate(der_bytes: &[u8]) -> Result<CertificateInfo> {
        let (_, cert) = X509Certificate::from_der(der_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse certificate: {:?}", e),
            }
        })?;

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
                        let addr_str = match ip.len() {
                            4 => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                            16 => {
                                let arr: [u8; 16] = (*ip).try_into().unwrap_or([0; 16]);
                                format!("{}", std::net::Ipv6Addr::from(arr))
                            }
                            _ => format!("IP:{}", hex::encode(ip)),
                        };
                        san.push(addr_str);
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
            .ok()
            .flatten()
            .map(|ext| ext.value.ca)
            .unwrap_or(false);

        // Get public key size (key_size() returns size in bits for RSA modulus)
        let public_key_size = match cert.public_key().parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => Some(rsa.key_size()),
            Ok(x509_parser::public_key::PublicKey::EC(ec)) => Some(ec.key_size()),
            _ => None,
        };

        // Check for Extended Validation (EV) certificate
        let (extended_validation, ev_oids) = super::extraction::check_extended_validation(&cert)?;

        // Calculate Pin SHA256 (HPKP) for the certificate's public key
        // Extract RSA public key exponent if the key is RSA
        let rsa_exponent = super::extraction::extract_rsa_exponent(der_bytes)
            .ok()
            .flatten();

        // Calculate certificate fingerprint SHA256
        // This is the SHA256 hash of the entire DER-encoded certificate
        let fingerprint_sha256 = super::fingerprints::calculate_fingerprint_sha256(der_bytes)
            .ok()
            .flatten();
        // This is used for HTTP Public Key Pinning per RFC 7469
        let pin_sha256 = super::fingerprints::calculate_pin_sha256(der_bytes)
            .ok()
            .flatten();

        // Calculate expiry countdown
        let not_after_str = cert.validity().not_after.to_string();
        let expiry_countdown = super::fingerprints::format_expiry_countdown(&not_after_str);

        // Check for Debian weak key (CVE-2008-0166)
        let debian_weak_key = super::checks::check_debian_weak_key(der_bytes);

        // Extract AIA URL (CA Issuers URL for intermediate cert download)
        let aia_url = super::extraction::extract_aia_url(&cert).ok().flatten();

        // Check for Certificate Transparency (SCT extension)
        let certificate_transparency = super::checks::check_certificate_transparency(&cert);

        Ok(CertificateInfo {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            serial_number: format!("{:x}", cert.serial),
            not_before: cert.validity().not_before.to_string(),
            not_after: not_after_str,
            expiry_countdown,
            signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
            public_key_algorithm: cert.public_key().algorithm.algorithm.to_string(),
            public_key_size,
            rsa_exponent,
            san,
            is_ca,
            key_usage,
            extended_key_usage,
            extended_validation,
            ev_oids,
            pin_sha256,
            fingerprint_sha256,
            debian_weak_key,
            aia_url,
            certificate_transparency,
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
            .ok_or_else(|| crate::error::TlsError::Other("No certificates in chain".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::network::Target;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_get_certificate_chain() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("Failed to parse target");
        let parser = CertificateParser::new(target);

        let chain = parser
            .get_certificate_chain()
            .await
            .expect("Failed to get certificate chain");

        assert!(chain.chain_length > 0);
        assert!(!chain.certificates.is_empty());

        // Verify chain_size_bytes is calculated correctly
        let expected_size: usize = chain.certificates.iter().map(|c| c.der_bytes.len()).sum();
        assert_eq!(
            chain.chain_size_bytes, expected_size,
            "Chain size should match sum of DER bytes"
        );
        assert!(
            chain.chain_size_bytes > 0,
            "Chain size should be greater than 0"
        );

        let leaf = chain.leaf().expect("Chain should have a leaf certificate");
        assert!(!leaf.subject.is_empty());
        assert!(!leaf.san.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_get_leaf_certificate() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("Failed to parse target");
        let parser = CertificateParser::new(target);

        let cert = parser
            .get_leaf_certificate()
            .await
            .expect("Failed to get leaf certificate");

        assert!(!cert.subject.is_empty());
        assert!(!cert.issuer.is_empty());
        assert!(cert.public_key_size.is_some());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_pin_sha256_calculation() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("Failed to parse target");
        let parser = CertificateParser::new(target);

        let cert = parser
            .get_leaf_certificate()
            .await
            .expect("Failed to get leaf certificate");

        // Verify that pin_sha256 was calculated
        assert!(cert.pin_sha256.is_some(), "Pin SHA256 should be calculated");

        let pin = cert.pin_sha256.expect("Pin SHA256 should be present");

        // Verify it's a valid Base64 string with expected length
        // SHA256 produces 32 bytes, Base64 encoding results in 44 characters (with padding)
        assert_eq!(
            pin.len(),
            44,
            "Pin SHA256 should be 44 characters (Base64-encoded SHA256)"
        );

        // Verify it ends with '=' padding (typical for Base64)
        assert!(
            pin.ends_with('=')
                || pin
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '+' || c == '/'),
            "Pin should be valid Base64"
        );

        println!("Calculated Pin SHA256 for google.com: {}", pin);
    }

    #[test]
    fn test_parse_certificate_basic_fields() {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest as OpensslMessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "example.com").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();

        let mut san = SubjectAlternativeName::new();
        san.dns("example.com");
        san.dns("www.example.com");
        let san_ext = san.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(san_ext).unwrap();

        builder.sign(&pkey, OpensslMessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let der = cert.to_der().unwrap();

        let info = CertificateParser::parse_certificate(&der).unwrap();
        assert!(info.subject.contains("CN=example.com"));
        assert!(info.issuer.contains("CN=example.com"));
        assert!(info.san.iter().any(|s| s.contains("example.com")));
        assert!(info.fingerprint_sha256.is_some());
    }
}
