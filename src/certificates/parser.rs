// Certificate Parser - Extract and parse certificate chains from TLS connections

use crate::Result;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use base64::Engine;
use chrono::{DateTime, Utc};
use openssl::hash::MessageDigest;
use openssl::x509::X509 as OpensslX509;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use x509_parser::prelude::*;

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

/// Certificate parser
pub struct CertificateParser {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    mtls_config: Option<MtlsConfig>,
}

/// Known Extended Validation (EV) Policy OIDs
/// These OIDs identify EV certificates from major Certificate Authorities
const EV_POLICY_OIDS: &[&str] = &[
    // DigiCert
    "2.16.840.1.114412.2.1",     // DigiCert EV SSL/TLS
    "2.16.840.1.114412.1.3.0.2", // DigiCert EV Code Signing
    // Entrust
    "2.16.840.1.114028.10.1.2", // Entrust EV SSL
    // Comodo/Sectigo
    "1.3.6.1.4.1.6449.1.2.1.5.1", // Comodo/Sectigo EV SSL
    // GlobalSign
    "1.3.6.1.4.1.4146.1.1", // GlobalSign EV SSL
    // SwissSign
    "2.16.756.1.89.1.2.1.1", // SwissSign EV Gold CA
    // Network Solutions
    "1.3.6.1.4.1.782.1.2.1.8.1", // Network Solutions EV SSL
    // QuoVadis
    "1.3.6.1.4.1.8024.0.2.100.1.2", // QuoVadis EV SSL
    // GoDaddy
    "2.16.840.1.114413.1.7.23.3", // GoDaddy EV SSL
    // Thawte
    "2.16.840.1.113733.1.7.48.1", // Thawte EV SSL
    // VeriSign/Symantec
    "2.16.840.1.113733.1.7.23.6", // VeriSign/Symantec EV SSL
    // Certum
    "1.2.616.1.113527.2.5.1.1", // Certum EV SSL
    // Let's Encrypt (for completeness, though they don't issue EV)
    // "2.23.140.1.1" is the CA/Browser Forum EV Guidelines OID
    "2.23.140.1.1", // CA/Browser Forum EV Certificate
    // GlobalSign Extended Validation
    "1.3.6.1.4.1.4146.1.10", // GlobalSign EV Code Signing
    // Buypass
    "2.16.578.1.26.1.3.3", // Buypass EV SSL
    // SECOM Trust Systems
    "1.2.392.200091.100.721.1", // SECOM Trust Systems EV SSL
    // TÜRKTRUST
    "2.16.792.3.0.4.1.1.4", // TÜRKTRUST EV SSL
    // E-Tugra
    "2.16.792.1.2.1.1.5.7.1.9", // E-Tugra EV SSL
    // Certinomis
    "1.2.250.1.177.1.18.2.2", // Certinomis EV SSL
    // AC Camerfirma
    "1.3.6.1.4.1.17326.10.14.2.1.2", // AC Camerfirma EV SSL
    // Actalis
    "1.3.159.1.17.1", // Actalis EV SSL
    // China Internet Network Information Center (CNNIC)
    "1.2.156.112570.1.1.3", // CNNIC EV SSL
];

/// Check if certificate contains Extended Validation (EV) policy OIDs
///
/// EV certificates are identified by specific Policy Identifier OIDs in the
/// Certificate Policies extension (OID 2.5.29.32). This function extracts
/// all policy OIDs and checks if any match known EV policy OIDs.
///
/// Returns: (is_ev, list_of_policy_oids)
fn check_extended_validation(cert: &X509Certificate) -> Result<(bool, Vec<String>)> {
    let mut policy_oids = Vec::new();
    let mut is_ev = false;

    // Try to get Certificate Policies extension (OID 2.5.29.32)
    if let Ok(Some(ext)) =
        cert.get_extension_unique(&oid_registry::OID_X509_EXT_CERTIFICATE_POLICIES)
    {
        // Parse the extension as Certificate Policies
        if let ParsedExtension::CertificatePolicies(policies) = ext.parsed_extension() {
            // policies is a &Vec<PolicyInformation>, iterate directly
            for policy in policies.iter() {
                let oid_str = policy.policy_id.to_id_string();
                policy_oids.push(oid_str.clone());

                // Check if this OID matches any known EV OID
                if EV_POLICY_OIDS.contains(&oid_str.as_str()) {
                    is_ev = true;
                }
            }
        }
    }

    Ok((is_ev, policy_oids))
}

/// Calculate Pin SHA256 for HPKP (HTTP Public Key Pinning) per RFC 7469
///
/// This function calculates the Base64-encoded SHA256 hash of the certificate's
/// SubjectPublicKeyInfo (SPKI) in DER format. This is the standard format used
/// for Public Key Pinning as defined in RFC 7469.
///
/// Algorithm:
/// 1. Extract the SubjectPublicKeyInfo from the certificate
/// 2. Compute SHA256 hash of the SPKI in DER format
/// 3. Base64-encode the hash
///
/// The pin can be used for HPKP headers and certificate validation.
///
/// # Arguments
/// * `der_bytes` - The certificate in DER format
///
/// # Returns
/// * `Ok(Some(String))` - Base64-encoded SHA256 pin on success
/// * `Ok(None)` - If public key cannot be extracted
/// * `Err` - On certificate parsing errors
fn calculate_pin_sha256(der_bytes: &[u8]) -> Result<Option<String>> {
    // Parse certificate using OpenSSL (which provides public_key_to_der)
    let cert = OpensslX509::from_der(der_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate with OpenSSL: {}", e))?;

    // Extract public key
    let public_key = cert
        .public_key()
        .map_err(|e| anyhow::anyhow!("Failed to extract public key: {}", e))?;

    // Get SubjectPublicKeyInfo in DER format
    // This is the SPKI (SubjectPublicKeyInfo) structure, which includes:
    // - Algorithm identifier
    // - Public key bit string
    let spki_der = public_key
        .public_key_to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode public key to DER: {}", e))?;

    // Calculate SHA256 hash of SPKI
    let digest = openssl::hash::hash(MessageDigest::sha256(), &spki_der)
        .map_err(|e| anyhow::anyhow!("Failed to compute SHA256 hash: {}", e))?;

    // Base64 encode the hash
    let pin = base64::engine::general_purpose::STANDARD.encode(digest);

    Ok(Some(pin))
}

/// Extract RSA public key exponent from certificate
///
/// This function extracts the public exponent (e) from RSA public keys.
/// The exponent is formatted as "e {number}" to match SSL Labs display format.
///
/// # Arguments
/// * `der_bytes` - The certificate in DER format
///
/// # Returns
/// * `Ok(Some(String))` - Formatted exponent (e.g., "e 65537") for RSA keys
/// * `Ok(None)` - For non-RSA keys (ECDSA, EdDSA, etc.)
/// * `Err` - On certificate parsing errors
fn extract_rsa_exponent(der_bytes: &[u8]) -> Result<Option<String>> {
    // Parse certificate using OpenSSL
    let cert = OpensslX509::from_der(der_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate with OpenSSL: {}", e))?;

    // Extract public key
    let public_key = cert
        .public_key()
        .map_err(|e| anyhow::anyhow!("Failed to extract public key: {}", e))?;

    // Try to extract RSA key - returns None if not RSA
    match public_key.rsa() {
        Ok(rsa) => {
            // Get the public exponent
            let exponent = rsa.e();
            // Convert BigNum to decimal string
            let exponent_str = exponent
                .to_dec_str()
                .map_err(|e| anyhow::anyhow!("Failed to convert exponent to string: {}", e))?;
            // Format as "e {number}" to match SSL Labs format
            Ok(Some(format!("e {}", exponent_str)))
        }
        Err(_) => {
            // Not an RSA key (could be ECDSA, EdDSA, etc.)
            Ok(None)
        }
    }
}

/// Calculate certificate fingerprint SHA256
///
/// This function calculates the SHA256 hash of the entire DER-encoded certificate,
/// formatted as a colon-separated hex string (e.g., "44:69:4E:E4:...").
/// This is the same format shown by SSL Labs and other certificate analysis tools.
///
/// Algorithm:
/// 1. Compute SHA256 hash of the entire DER-encoded certificate
/// 2. Format as uppercase hex string with colon separators
///
/// # Arguments
/// * `der_bytes` - The certificate in DER format
///
/// # Returns
/// * `Ok(Some(String))` - Colon-separated hex SHA256 fingerprint on success
/// * `Err` - On hash calculation errors
fn calculate_fingerprint_sha256(der_bytes: &[u8]) -> Result<Option<String>> {
    // Calculate SHA256 hash of entire certificate
    let digest = openssl::hash::hash(MessageDigest::sha256(), der_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to compute SHA256 hash: {}", e))?;

    // Format as colon-separated hex string (uppercase)
    let fingerprint = digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    Ok(Some(fingerprint))
}

/// Extract Authority Information Access (AIA) CA Issuers URL from certificate
///
/// This function extracts the CA Issuers URL from the AIA extension (OID 1.3.6.1.5.5.7.1.1).
/// The CA Issuers URL points to the location where the issuer's certificate can be downloaded,
/// which is useful for building the certificate chain.
///
/// This is different from the OCSP URL (also in AIA) which is used for revocation checking.
///
/// # Arguments
/// * `cert` - X.509 certificate to extract AIA URL from
///
/// # Returns
/// * `Ok(Some(String))` - CA Issuers URL if present
/// * `Ok(None)` - If AIA extension not present or no CA Issuers URL
/// * `Err` - On parsing errors
fn extract_aia_url(cert: &X509Certificate) -> Result<Option<String>> {
    // Look for Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1)
    if let Ok(Some(ext)) = cert.get_extension_unique(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
        && let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension()
    {
        for access_desc in &aia.accessdescs {
            // CA Issuers OID: 1.3.6.1.5.5.7.48.2
            if access_desc.access_method.to_string() == "1.3.6.1.5.5.7.48.2"
                && let GeneralName::URI(uri) = &access_desc.access_location
            {
                return Ok(Some(uri.to_string()));
            }
        }
    }

    Ok(None)
}

/// Calculate years, months, and remaining days from a total number of days.
fn calculate_duration_parts(days: i64) -> (i64, i64, i64) {
    let years = days / 365;
    let remaining_days = days % 365;
    let months = remaining_days / 30;
    let final_days = remaining_days % 30;
    (years, months, final_days)
}

/// Format a time phrase for certificate expiry display.
fn format_time_phrase(years: i64, months: i64, days: i64, is_expired: bool) -> String {
    let (prefix, suffix) = if is_expired {
        ("expired ", " ago")
    } else {
        ("expires in ", "")
    };

    fn pluralize(n: i64, singular: &str) -> String {
        if n == 1 {
            format!("1 {}", singular)
        } else {
            format!("{} {}s", n, singular)
        }
    }

    let phrase = if years > 0 {
        if months > 0 {
            format!(
                "{} and {}",
                pluralize(years, "year"),
                pluralize(months, "month")
            )
        } else {
            pluralize(years, "year")
        }
    } else if months > 0 {
        if days > 0 {
            format!(
                "{} and {}",
                pluralize(months, "month"),
                pluralize(days, "day")
            )
        } else {
            pluralize(months, "month")
        }
    } else {
        pluralize(days, "day")
    };

    format!("{}{}{}", prefix, phrase, suffix)
}

fn format_expiry_countdown(not_after_str: &str) -> Option<String> {
    use chrono::NaiveDateTime;

    let not_after = chrono::DateTime::parse_from_rfc3339(not_after_str)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDateTime::parse_from_str(not_after_str, "%Y-%m-%d %H:%M:%S UTC")
                .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
        })
        .or_else(|_| {
            let cleaned = not_after_str.replace(" UTC", "").replace(" GMT", "");
            NaiveDateTime::parse_from_str(&cleaned, "%Y-%m-%d %H:%M:%S")
                .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
        })
        .ok()?;

    let duration = not_after.signed_duration_since(Utc::now());
    let is_expired = duration.num_seconds() < 0;
    let total_days = duration.num_days().abs();

    if total_days == 0 {
        return Some(
            if is_expired {
                "expired today"
            } else {
                "expires today"
            }
            .to_string(),
        );
    }

    let (years, months, days) = calculate_duration_parts(total_days);
    Some(format_time_phrase(years, months, days, is_expired))
}

/// Check if certificate uses a Debian weak key (CVE-2008-0166)
///
/// This function checks the certificate against the Debian weak key database.
///
/// # Arguments
/// * `der_bytes` - DER-encoded certificate
///
/// # Returns
/// * `Some(true)` - Certificate uses a known Debian weak key
/// * `Some(false)` - Certificate does not use a weak key
/// * `None` - Unable to check (parsing error)
fn check_debian_weak_key(der_bytes: &[u8]) -> Option<bool> {
    match OpensslX509::from_der(der_bytes) {
        Ok(cert) => crate::vulnerabilities::debian_keys::is_debian_weak_key(&cert).ok(),
        Err(_) => None,
    }
}

/// Check for Certificate Transparency (CT) SCT extension in certificate
///
/// This function checks if the certificate contains Signed Certificate Timestamps (SCTs)
/// embedded in the X.509 extension with OID 1.3.6.1.4.1.11129.2.4.2.
///
/// # Arguments
/// * `cert` - X.509 certificate to check
///
/// # Returns
/// * `Some("Yes (certificate)")` - Certificate has SCT extension
/// * `Some("No")` - Certificate does not have SCT extension
/// * `None` - Unable to check (parsing error)
fn check_certificate_transparency(cert: &X509Certificate) -> Option<String> {
    // SCT extension OID: 1.3.6.1.4.1.11129.2.4.2
    const SCT_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

    // Look for SCT extension
    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == SCT_EXTENSION_OID {
            // SCT extension found - certificate contains embedded SCTs
            return Some("Yes (certificate)".to_string());
        }
    }

    // No SCT extension found
    Some("No".to_string())
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
            return Err(anyhow::anyhow!("No certificates received from server").into());
        }

        let certs = peer_certificates
            .ok_or_else(|| anyhow::anyhow!("No certificates received from server"))?;
        let mut parsed_certs = Vec::new();

        for cert_der in certs {
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
        let (extended_validation, ev_oids) = check_extended_validation(&cert)?;

        // Calculate Pin SHA256 (HPKP) for the certificate's public key
        // Extract RSA public key exponent if the key is RSA
        let rsa_exponent = extract_rsa_exponent(der_bytes).ok().flatten();

        // Calculate certificate fingerprint SHA256
        // This is the SHA256 hash of the entire DER-encoded certificate
        let fingerprint_sha256 = calculate_fingerprint_sha256(der_bytes).ok().flatten();
        // This is used for HTTP Public Key Pinning per RFC 7469
        let pin_sha256 = calculate_pin_sha256(der_bytes).ok().flatten();

        // Calculate expiry countdown
        let not_after_str = cert.validity().not_after.to_string();
        let expiry_countdown = format_expiry_countdown(&not_after_str);

        // Check for Debian weak key (CVE-2008-0166)
        let debian_weak_key = check_debian_weak_key(der_bytes);

        // Extract AIA URL (CA Issuers URL for intermediate cert download)
        let aia_url = extract_aia_url(&cert).ok().flatten();

        // Check for Certificate Transparency (SCT extension)
        let certificate_transparency = check_certificate_transparency(&cert);

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

    /// Check if certificate uses a Debian weak key (CVE-2008-0166)
    ///
    /// Wrapper around the debian_keys module detector
    #[allow(dead_code)]
    fn check_debian_weak_key_cert(&self, cert_info: &CertificateInfo) -> Result<Option<bool>> {
        if cert_info.der_bytes.is_empty() {
            return Ok(None);
        }

        match OpensslX509::from_der(&cert_info.der_bytes) {
            Ok(cert) => match crate::vulnerabilities::debian_keys::is_debian_weak_key(&cert) {
                Ok(is_weak) => Ok(Some(is_weak)),
                Err(_) => Ok(None),
            },
            Err(_) => Ok(None),
        }
    }

    /// Get leaf certificate (first in chain)
    pub async fn get_leaf_certificate(&self) -> Result<CertificateInfo> {
        let chain = self.get_certificate_chain().await?;
        Ok(chain
            .certificates
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No certificates in chain"))?)
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
        self.certificates.last().is_some_and(|c| c.is_ca)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_ev_oids_list() {
        // Test that the EV OIDs list contains known EV CAs
        assert!(EV_POLICY_OIDS.contains(&"2.16.840.1.114412.2.1")); // DigiCert
        assert!(EV_POLICY_OIDS.contains(&"1.3.6.1.4.1.6449.1.2.1.5.1")); // Comodo/Sectigo
        assert!(EV_POLICY_OIDS.contains(&"1.3.6.1.4.1.4146.1.1")); // GlobalSign
        assert!(EV_POLICY_OIDS.contains(&"2.23.140.1.1")); // CA/Browser Forum
    }

    #[test]
    fn test_check_extended_validation_detection() {
        // This test verifies that the check_extended_validation function correctly
        // identifies EV certificates based on Certificate Policies extension.
        // Note: This is a unit test that would require a real certificate with
        // EV policy OIDs to fully validate. For now, we just ensure the function
        // signature is correct and the OID list is populated.
        #[allow(clippy::absurd_extreme_comparisons)]
        {
            assert!(!EV_POLICY_OIDS.is_empty());
        }
        assert!(EV_POLICY_OIDS.len() > 20); // Should have many known EV OIDs
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
    fn test_calculate_pin_sha256_function() {
        // Test the calculate_pin_sha256 function with a self-generated certificate
        use openssl::asn1::Asn1Time;
        use openssl::bn::{BigNum, MsbOption};
        use openssl::hash::MessageDigest as OpensslMessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        // Generate RSA key pair
        let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");
        let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey from RSA");

        // Create certificate builder
        let mut builder = X509Builder::new().expect("Failed to create X509Builder");
        builder.set_version(2).expect("Failed to set version");

        let mut serial = BigNum::new().expect("Failed to create BigNum");
        serial
            .rand(128, MsbOption::MAYBE_ZERO, false)
            .expect("Failed to generate random serial");
        let serial = serial
            .to_asn1_integer()
            .expect("Failed to convert to ASN1 integer");
        builder
            .set_serial_number(&serial)
            .expect("Failed to set serial number");

        // Set subject name
        let mut name_builder = X509NameBuilder::new().expect("Failed to create X509NameBuilder");
        name_builder
            .append_entry_by_text("C", "US")
            .expect("Failed to set country");
        name_builder
            .append_entry_by_text("O", "Test")
            .expect("Failed to set organization");
        name_builder
            .append_entry_by_text("CN", "test.example.com")
            .expect("Failed to set common name");
        let name = name_builder.build();
        builder
            .set_subject_name(&name)
            .expect("Failed to set subject name");
        builder
            .set_issuer_name(&name)
            .expect("Failed to set issuer name");

        // Set validity period
        let not_before = Asn1Time::days_from_now(0).expect("Failed to create not_before time");
        let not_after = Asn1Time::days_from_now(365).expect("Failed to create not_after time");
        builder
            .set_not_before(&not_before)
            .expect("Failed to set not_before");
        builder
            .set_not_after(&not_after)
            .expect("Failed to set not_after");

        // Set public key
        builder.set_pubkey(&pkey).expect("Failed to set public key");

        // Sign the certificate
        builder
            .sign(&pkey, OpensslMessageDigest::sha256())
            .expect("Failed to sign certificate");
        let cert = builder.build();

        // Get DER bytes
        let der_bytes = cert.to_der().expect("Failed to convert certificate to DER");

        // Calculate pin
        let pin = calculate_pin_sha256(&der_bytes).expect("Failed to calculate pin SHA256");

        assert!(
            pin.is_some(),
            "Pin should be calculated for self-signed cert"
        );
        assert_eq!(
            pin.as_ref().expect("Pin should be Some").len(),
            44,
            "Pin should be 44 characters"
        );

        println!(
            "Test certificate Pin SHA256: {}",
            pin.expect("Pin should be present")
        );
    }
}
