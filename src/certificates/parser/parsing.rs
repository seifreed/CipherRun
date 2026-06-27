use crate::Result;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;
use x509_parser::prelude::*;

use super::{CertificateChain, CertificateInfo};

/// Algorithm OID for Ed25519 signing/public keys (RFC 8410).
const ED25519_OID: &str = "1.3.101.112";
/// Algorithm OID for Ed448 signing/public keys (RFC 8410).
const ED448_OID: &str = "1.3.101.113";

/// Map a certificate's public-key algorithm to a stable, human-readable name.
///
/// x509-parser exposes the algorithm only as a numeric OID (e.g.
/// `1.2.840.10045.2.1`). Downstream key-strength and formatting logic classify
/// keys by name (`rsaEncryption`, `id-ecPublicKey`, `ed25519`, ...), so emit
/// those names here at the parse boundary. Ed25519/Ed448 keys parse as
/// `Unknown`, hence the OID check before falling back to the parsed key type.
fn public_key_algorithm_name(cert: &X509Certificate) -> String {
    let oid = cert.public_key().algorithm.algorithm.to_string();
    match oid.as_str() {
        ED25519_OID => return "ed25519".to_string(),
        ED448_OID => return "ed448".to_string(),
        _ => {}
    }

    use x509_parser::public_key::PublicKey;
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(_)) => "rsaEncryption".to_string(),
        Ok(PublicKey::EC(_)) => "id-ecPublicKey".to_string(),
        Ok(PublicKey::DSA(_)) => "dsaEncryption".to_string(),
        _ => oid,
    }
}

/// Map a certificate's signature algorithm to a stable, human-readable name.
///
/// x509-parser exposes the algorithm as a numeric OID (e.g.
/// `1.2.840.10045.4.3.2`), but compliance and policy rules match against
/// algorithm names (`ecdsa-with-SHA256`, `sha256WithRSAEncryption`, ...).
/// Resolve the OID short name via the registry, falling back to the numeric
/// OID for algorithms the registry does not know.
fn signature_algorithm_name(cert: &X509Certificate) -> String {
    let oid = &cert.signature_algorithm.algorithm;
    oid2sn(oid, oid_registry())
        .map(|sn| sn.to_string())
        .unwrap_or_else(|_| oid.to_string())
}

/// Certificate parser
pub struct CertificateParser {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    mtls_config: Option<MtlsConfig>,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
}

impl CertificateParser {
    /// Build the TLS server name for a target hostname.
    ///
    /// This accepts DNS names and raw IP literals. IP targets are converted to
    /// `ServerName::IpAddress`, which avoids treating them as invalid DNS
    /// names during certificate fetches.
    fn server_name_for_hostname(hostname: &str) -> Result<rustls_pki_types::ServerName<'static>> {
        crate::utils::network::server_name_for_hostname(hostname)
    }

    /// Create new certificate parser
    pub fn new(target: Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            mtls_config: None,
            starttls: None,
            starttls_hostname: None,
        }
    }

    /// Create new certificate parser with mTLS configuration
    pub fn with_mtls(target: Target, mtls_config: MtlsConfig) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            mtls_config: Some(mtls_config),
            starttls: None,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before the TLS handshake.
    ///
    /// Required for plaintext-first services (SMTP/IMAP/POP3/FTP/XMPP/…) that
    /// upgrade to TLS via a STARTTLS command. Without this the rustls handshake
    /// is sent against the plaintext greeting and fails with an
    /// `InvalidContentType` record error, so no certificate chain is retrieved.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
    }

    /// Get certificate chain from server
    pub async fn get_certificate_chain(&self) -> Result<CertificateChain> {
        // Use rustls to get the certificate chain
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // Connect TCP
        let mut stream =
            crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None).await?;

        // For plaintext-first services, upgrade the connection via STARTTLS
        // before the TLS handshake; otherwise rustls speaks TLS to the
        // plaintext greeting and aborts with an InvalidContentType error.
        if let Some(starttls_proto) = self.starttls {
            let hostname = self
                .starttls_hostname
                .clone()
                .unwrap_or_else(|| self.target.hostname.clone());
            let negotiator = crate::starttls::protocols::get_negotiator(starttls_proto, hostname);
            crate::starttls::protocols::negotiate_starttls_with_timeout(
                negotiator.as_ref(),
                &mut stream,
                self.read_timeout,
            )
            .await
            .map_err(|e| crate::TlsError::StarttlsError {
                protocol: starttls_proto.to_string(),
                details: format!("STARTTLS negotiation failed before certificate fetch: {e}"),
            })?;
        }

        // Build TLS connector with or without client auth.
        //
        // Server-certificate verification is intentionally disabled here: a
        // scanner must retrieve chains from servers with expired, self-signed,
        // untrusted, or hostname-mismatched certificates (a verifying client
        // would abort the handshake and produce no report). The retrieved
        // chain is assessed separately by `certificates::validator`.
        let connector = if let Some(ref mtls_config) = self.mtls_config {
            // Use mTLS configuration
            mtls_config.build_tls_connector()?
        } else {
            TlsConnector::from(Arc::new(
                crate::utils::insecure_tls::insecure_client_config(),
            ))
        };

        // Connect with TLS
        let domain = Self::server_name_for_hostname(&self.target.hostname)?;

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

        // Limit certificate chain size to prevent DoS and potential bypass attacks
        // A chain with >100 certs could hide a malicious cert after 99 valid ones
        const MAX_CERT_CHAIN_LENGTH: usize = 100;
        if certs.len() > MAX_CERT_CHAIN_LENGTH {
            return Err(crate::error::TlsError::CertificateError(
                crate::error::CertificateValidationError::InvalidChain {
                    reason: format!(
                        "Certificate chain too long ({} certs), maximum allowed is {}. This could indicate a malicious server attempting to bypass validation.",
                        certs.len(),
                        MAX_CERT_CHAIN_LENGTH
                    ),
                },
            ));
        }

        let certs_to_process = certs.iter();
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
        if let Some(ext) = cert
            .get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .map_err(|error| crate::CertificateValidationError::ParseError {
                details: format!("Invalid subject alternative name extension: {error}"),
            })?
        {
            match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san_gen) => {
                    for name in &san_gen.general_names {
                        match name {
                            GeneralName::DNSName(dns) => {
                                san.push(dns.to_string());
                            }
                            GeneralName::IPAddress(ip) => {
                                let addr_str = match ip.len() {
                                    4 => match <[u8; 4]>::try_from(*ip) {
                                        Ok(addr) => std::net::Ipv4Addr::from(addr).to_string(),
                                        Err(_) => {
                                            debug!(
                                                "Invalid IPv4 address length in SAN: {} bytes, expected 4",
                                                ip.len()
                                            );
                                            format!("IP:{}", hex::encode(ip))
                                        }
                                    },
                                    16 => {
                                        // Convert IPv6 bytes to address, handling malformed data gracefully
                                        let arr: [u8; 16] = match (*ip).try_into() {
                                            Ok(a) => a,
                                            Err(_) => {
                                                debug!(
                                                    "Invalid IPv6 address length in SAN: {} bytes, expected 16",
                                                    ip.len()
                                                );
                                                // Return unspecified address for malformed data
                                                [0; 16]
                                            }
                                        };
                                        format!("{}", std::net::Ipv6Addr::from(arr))
                                    }
                                    _ => format!("IP:{}", hex::encode(ip)),
                                };
                                san.push(addr_str);
                            }
                            other => {
                                debug!("Skipping non-DNS/IP SAN type: {:?}", other);
                            }
                        }
                    }
                }
                other => {
                    return Err(crate::CertificateValidationError::ParseError {
                        details: format!("Invalid subject alternative name extension: {other:?}"),
                    }
                    .into());
                }
            }
        }

        // Extract Key Usage
        let mut key_usage = Vec::new();
        if let Some(ext) = cert
            .get_extension_unique(&oid_registry::OID_X509_EXT_KEY_USAGE)
            .map_err(|error| crate::CertificateValidationError::ParseError {
                details: format!("Invalid key usage extension: {error}"),
            })?
        {
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(ku) => {
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
                other => {
                    return Err(crate::CertificateValidationError::ParseError {
                        details: format!("Invalid key usage extension: {other:?}"),
                    }
                    .into());
                }
            }
        }

        // Extract Extended Key Usage
        let mut extended_key_usage = Vec::new();
        if let Some(ext) = cert
            .get_extension_unique(&oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE)
            .map_err(|error| crate::CertificateValidationError::ParseError {
                details: format!("Invalid extended key usage extension: {error}"),
            })?
        {
            match ext.parsed_extension() {
                ParsedExtension::ExtendedKeyUsage(eku) => {
                    // x509-parser decodes the well-known EKU purposes into dedicated
                    // boolean fields; only genuinely unrecognized OIDs land in `other`.
                    // Reading the booleans is therefore the only reliable way to report
                    // Code Signing / Email Protection / Time Stamping / OCSP Signing.
                    if eku.any {
                        extended_key_usage.push("Any".to_string());
                    }
                    if eku.server_auth {
                        extended_key_usage.push("Server Authentication".to_string());
                    }
                    if eku.client_auth {
                        extended_key_usage.push("Client Authentication".to_string());
                    }
                    if eku.code_signing {
                        extended_key_usage.push("Code Signing".to_string());
                    }
                    if eku.email_protection {
                        extended_key_usage.push("Email Protection".to_string());
                    }
                    if eku.time_stamping {
                        extended_key_usage.push("Time Stamping".to_string());
                    }
                    if eku.ocsp_signing {
                        extended_key_usage.push("OCSP Signing".to_string());
                    }
                    for oid in eku.other.iter() {
                        extended_key_usage.push(format!("Unknown ({})", oid));
                    }
                }
                other => {
                    return Err(crate::CertificateValidationError::ParseError {
                        details: format!("Invalid extended key usage extension: {other:?}"),
                    }
                    .into());
                }
            }
        }

        // Check if CA certificate
        let mut is_ca = false;
        for ext in cert.extensions() {
            if ext.oid.to_id_string() != "2.5.29.19" {
                continue;
            }
            match ext.parsed_extension() {
                ParsedExtension::BasicConstraints(basic_constraints) => {
                    is_ca = basic_constraints.ca;
                }
                other => {
                    return Err(crate::CertificateValidationError::ParseError {
                        details: format!("Invalid basic constraints extension: {other:?}"),
                    }
                    .into());
                }
            }
        }

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
        let rsa_exponent = super::extraction::extract_rsa_exponent(der_bytes)?;

        // Calculate certificate fingerprint SHA256
        // This is the SHA256 hash of the entire DER-encoded certificate
        let fingerprint_sha256 = super::fingerprints::calculate_fingerprint_sha256(der_bytes)?;
        // This is used for HTTP Public Key Pinning per RFC 7469
        let pin_sha256 = super::fingerprints::calculate_pin_sha256(der_bytes)?;

        // Calculate expiry countdown
        let not_after_str = cert.validity().not_after.to_string();
        let expiry_countdown = super::fingerprints::format_expiry_countdown(&not_after_str);

        // Check for Debian weak key (CVE-2008-0166)
        let debian_weak_key = super::checks::check_debian_weak_key(der_bytes)?;

        // Extract AIA URL (CA Issuers URL for intermediate cert download)
        let aia_url = super::extraction::extract_aia_url(&cert)?;

        // Check for Certificate Transparency (SCT extension)
        let certificate_transparency = super::checks::check_certificate_transparency(&cert);

        Ok(CertificateInfo {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            serial_number: format!("{:x}", cert.serial),
            not_before: cert.validity().not_before.to_string(),
            not_after: not_after_str,
            expiry_countdown,
            signature_algorithm: signature_algorithm_name(&cert),
            public_key_algorithm: public_key_algorithm_name(&cert),
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

    fn cert_with_raw_extension_der(oid: &str, contents: &[u8]) -> Vec<u8> {
        use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::hash::MessageDigest as OpensslMessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "malformed-extension.example.com")
            .unwrap();
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

        let oid = Asn1Object::from_str(oid).unwrap();
        let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
        let extension = X509Extension::new_from_der(&oid, false, &contents).unwrap();
        builder.append_extension(extension).unwrap();
        builder.sign(&pkey, OpensslMessageDigest::sha256()).unwrap();

        builder.build().to_der().unwrap()
    }

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
        assert_eq!(info.rsa_exponent.as_deref(), Some("e 65537"));
        assert!(info.fingerprint_sha256.is_some());
    }

    #[test]
    fn test_parse_certificate_ec_key_reports_ec_algorithm_and_passes_strength() {
        use openssl::asn1::Asn1Time;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest as OpensslMessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "ec.example.com").unwrap();
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
        builder.sign(&pkey, OpensslMessageDigest::sha256()).unwrap();
        let der = builder.build().to_der().unwrap();

        let info = CertificateParser::parse_certificate(&der).unwrap();

        // x509-parser exposes only the numeric OID; the parser must normalize
        // it to a name the key-strength logic recognizes as elliptic-curve.
        assert_eq!(info.public_key_algorithm, "id-ecPublicKey");
        assert_eq!(info.public_key_size, Some(256));

        // Signature algorithm must resolve to a name (not a numeric OID), so
        // compliance/policy rules that match on "sha256" succeed.
        assert_eq!(info.signature_algorithm, "ecdsa-with-SHA256");

        // Regression: a 256-bit EC key must not be flagged as a weak RSA key.
        let validator =
            crate::certificates::validator::CertificateValidator::new("ec.example.com".to_string());
        let mut issues = Vec::new();
        assert!(validator.check_key_strength(&info, &mut issues));
        assert!(
            issues.is_empty(),
            "strong EC key should produce no key-strength issues, got: {:?}",
            issues
        );
    }

    #[test]
    fn test_parse_certificate_rejects_malformed_basic_constraints() {
        let der = cert_with_raw_extension_der("2.5.29.19", b"\x05\x00");
        let error = CertificateParser::parse_certificate(&der)
            .expect_err("malformed basic constraints should fail");

        assert!(
            error
                .to_string()
                .contains("Invalid basic constraints extension")
        );
    }

    #[test]
    fn test_parse_certificate_rejects_malformed_subject_alt_name() {
        let der = cert_with_raw_extension_der("2.5.29.17", b"\x05\x00");
        let error =
            CertificateParser::parse_certificate(&der).expect_err("malformed SAN should fail");

        assert!(
            error
                .to_string()
                .contains("Invalid subject alternative name extension")
        );
    }

    #[test]
    fn test_parse_certificate_rejects_malformed_certificate_policies() {
        let der = cert_with_raw_extension_der("2.5.29.32", b"\x05\x00");
        let error = CertificateParser::parse_certificate(&der)
            .expect_err("malformed certificate policies should fail");

        assert!(
            error
                .to_string()
                .contains("Invalid certificate policies extension")
        );
    }

    #[test]
    fn test_parse_certificate_rejects_malformed_aia() {
        let der = cert_with_raw_extension_der("1.3.6.1.5.5.7.1.1", b"\x05\x00");
        let error =
            CertificateParser::parse_certificate(&der).expect_err("malformed AIA should fail");

        assert!(
            error
                .to_string()
                .contains("Authority Information Access extension")
        );
    }

    #[test]
    fn test_server_name_for_ipv4_literal_uses_ip_address_variant() {
        let server_name = CertificateParser::server_name_for_hostname("93.184.216.34").unwrap();
        assert!(matches!(
            server_name,
            rustls_pki_types::ServerName::IpAddress(_)
        ));
    }

    #[test]
    fn test_server_name_for_ipv6_literal_uses_ip_address_variant() {
        let server_name = CertificateParser::server_name_for_hostname("2001:db8::1").unwrap();
        assert!(matches!(
            server_name,
            rustls_pki_types::ServerName::IpAddress(_)
        ));
    }
}
