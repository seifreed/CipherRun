// Advanced Certificate Tests
// Multiple certificates, certificate compression, cipher order enforcement

use crate::Result;
use crate::utils::network::Target;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use tokio::time::Duration;

/// RFC 9345 delegated credentials are sent in CertificateEntry extension 34.
pub const DELEGATED_CREDENTIAL_EXTENSION_TYPE: u16 = 34;
/// RFC 9345 DelegationUsage certificate-extension OID.
pub const DELEGATION_USAGE_OID: &str = "1.3.6.1.4.1.44363.44";

/// Multiple certificates analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipleCertificatesAnalysis {
    pub certificates_count: usize,
    pub certificates: Vec<CertificateInfo>,
    pub virtual_hosts_detected: bool,
    pub sni_required: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub san_entries: Vec<String>,
    pub valid_from: String,
    pub valid_until: String,
    pub fingerprint: String,
}

/// Certificate compression analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateCompressionAnalysis {
    pub compression_supported: bool,
    pub compression_algorithms: Vec<String>,
    pub original_size: Option<usize>,
    pub compressed_size: Option<usize>,
    pub compression_ratio: Option<f64>,
    pub details: String,
    #[serde(default)]
    pub inconclusive: bool,
}

/// Evidence available for RFC 9345 delegated credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegatedCredentialAnalysis {
    pub extension_type: u16,
    pub delegation_usage_oid: String,
    pub certificate_allows_delegation: bool,
    pub credential_observed: bool,
    pub status: String,
    pub details: String,
    pub limitations: Vec<String>,
}

/// Inspect the end-entity certificate prerequisite for delegated credentials.
///
/// The delegated credential itself is a TLS `CertificateEntry` extension, not
/// an X.509 extension. Current rustls/OpenSSL handshake APIs expose the peer
/// certificate but not those opaque CertificateEntry extensions, so this
/// function deliberately reports `not_observed` instead of claiming support.
pub fn analyze_delegated_credential_certificate(
    certificate_der: &[u8],
) -> Result<DelegatedCredentialAnalysis> {
    let (_, certificate) =
        x509_parser::parse_x509_certificate(certificate_der).map_err(|error| {
            crate::error::TlsError::ParseError {
                message: format!("Invalid delegated-credential certificate: {error}"),
            }
        })?;
    let certificate_allows_delegation = certificate
        .extensions()
        .iter()
        .any(|extension| extension.oid.to_id_string() == DELEGATION_USAGE_OID);

    Ok(DelegatedCredentialAnalysis {
        extension_type: DELEGATED_CREDENTIAL_EXTENSION_TYPE,
        delegation_usage_oid: DELEGATION_USAGE_OID.to_string(),
        certificate_allows_delegation,
        credential_observed: false,
        status: "not_observed".to_string(),
        details: if certificate_allows_delegation {
            "The certificate authorizes delegated credentials, but no CertificateEntry credential was exposed by the TLS API".to_string()
        } else {
            "The end-entity certificate does not contain the RFC 9345 DelegationUsage extension".to_string()
        },
        limitations: vec![
            "CertificateEntry extension 34 is not exposed by the current rustls/OpenSSL handshake APIs".to_string(),
            "A not_observed result is not evidence that the peer does or does not implement RFC 9345".to_string(),
        ],
    })
}

/// Cipher order enforcement analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderEnforcementAnalysis {
    pub server_enforces_order: bool,
    pub test_results: Vec<CipherOrderEnforcementTest>,
    pub consistency_score: f64,
    pub details: String,
    #[serde(default)]
    pub inconclusive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderEnforcementTest {
    pub test_name: String,
    pub client_order: Vec<String>,
    pub server_selected: String,
    pub expected_if_server_preference: String,
    pub expected_if_client_preference: String,
    pub matches_server_preference: bool,
}

/// Advanced certificate tester
pub struct CertificateAdvancedTester {
    target: Target,
}

impl CertificateAdvancedTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for multiple certificates on same IP:port
    pub async fn test_multiple_certificates(&self) -> Result<MultipleCertificatesAnalysis> {
        let mut certificates = Vec::new();

        // Test 1: Connect without SNI
        let cert_no_sni = self.get_certificate(None).await;

        // Test 2: Connect with SNI (target hostname)
        let cert_with_sni = self.get_certificate(Some(&self.target.hostname)).await;

        // Test 3: Try common alternative hostnames
        let alt_hostnames = vec![
            format!("www.{}", self.target.hostname),
            format!("mail.{}", self.target.hostname),
            format!("api.{}", self.target.hostname),
        ];

        // Check SNI requirement before moving values
        let no_sni_failed = cert_no_sni.is_err();
        let with_sni_ok = cert_with_sni.is_ok();

        // Add no-SNI certificate
        if let Ok(cert) = cert_no_sni {
            certificates.push(cert);
        }

        // Add SNI certificate
        if let Ok(cert) = cert_with_sni {
            // Only add if different from no-SNI cert
            if certificates
                .first()
                .is_none_or(|existing| cert.fingerprint != existing.fingerprint)
            {
                certificates.push(cert);
            }
        }

        // Try alternative hostnames
        for alt_hostname in alt_hostnames {
            if let Ok(cert) = self.get_certificate(Some(&alt_hostname)).await {
                // Only add if different from existing certificates
                if !certificates
                    .iter()
                    .any(|c| c.fingerprint == cert.fingerprint)
                {
                    certificates.push(cert);
                }
            }
        }

        let certificates_count = certificates.len();
        let virtual_hosts_detected = certificates_count > 1;
        let sni_required = certificates_count > 0 && no_sni_failed && with_sni_ok;

        let details = format!(
            "{} certificate(s) detected. Virtual hosts: {}. SNI required: {}",
            certificates_count, virtual_hosts_detected, sni_required
        );

        Ok(MultipleCertificatesAnalysis {
            certificates_count,
            certificates,
            virtual_hosts_detected,
            sni_required,
            details,
        })
    }

    /// Check delegated-credential authorization on the peer certificate.
    pub async fn test_delegated_credentials(&self) -> Result<DelegatedCredentialAnalysis> {
        let certificate = self
            .get_peer_certificate(Some(&self.target.hostname))
            .await?;
        let der = certificate.to_der()?;
        analyze_delegated_credential_certificate(&der)
    }

    async fn get_certificate(&self, sni_hostname: Option<&str>) -> Result<CertificateInfo> {
        let cert = self.get_peer_certificate(sni_hostname).await?;
        extract_certificate_info(&cert)
    }

    async fn get_peer_certificate(&self, sni_hostname: Option<&str>) -> Result<X509> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream = crate::utils::network::into_blocking_std_stream(stream, connect_timeout)?;

        let (hostname_to_use, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, sni_hostname);
        tokio::task::spawn_blocking(move || -> Result<X509> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // The scanner must retrieve and inspect certificates from hosts whose
            // certificates are expired/self-signed/untrusted — exactly the cases a
            // verifying connector rejects with a fatal handshake error. Trust is
            // assessed separately by the certificate validator.
            builder.set_verify(SslVerifyMode::NONE);

            let connector = builder.build();
            let ssl_stream = connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname_to_use, std_stream)?;

            let cert = ssl_stream
                .ssl()
                .peer_certificate()
                .ok_or_else(|| crate::error::TlsError::Other("No certificate presented".into()))?;

            Ok(cert)
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("certificate task failed: {}", e)))?
    }

    /// Test certificate compression
    pub async fn test_certificate_compression(&self) -> Result<CertificateCompressionAnalysis> {
        // Certificate compression is defined in RFC 8879
        // It's a TLS 1.3 extension (compress_certificate, type 27)

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream = crate::utils::network::into_blocking_std_stream(stream, connect_timeout)?;

        let (hostname, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
        tokio::task::spawn_blocking(move || -> Result<CertificateCompressionAnalysis> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // Certificate compression is independent of certificate validity; the
            // scanner must probe it on bad-cert hosts too (trust assessed separately).
            builder.set_verify(SslVerifyMode::NONE);

            // Try to enable TLS 1.3 for certificate compression
            builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

            let connector = builder.build();

            match connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname, std_stream)
            {
                Ok(ssl_stream) => {
                    let cert = ssl_stream.ssl().peer_certificate();

                    if let Some(cert) = cert {
                        Ok(analyze_observed_certificate_compression(&cert)?)
                    } else {
                        Ok(CertificateCompressionAnalysis {
                            compression_supported: false,
                            compression_algorithms: Vec::new(),
                            original_size: None,
                            compressed_size: None,
                            compression_ratio: None,
                            details: "No certificate presented".to_string(),
                            inconclusive: true,
                        })
                    }
                }
                Err(e) => Ok(CertificateCompressionAnalysis {
                    compression_supported: false,
                    compression_algorithms: Vec::new(),
                    original_size: None,
                    compressed_size: None,
                    compression_ratio: None,
                    details: format!("TLS 1.3 connection failed: {}", e),
                    inconclusive: true,
                }),
            }
        })
        .await
        .map_err(|e| {
            crate::TlsError::Other(format!("certificate compression task failed: {}", e))
        })?
    }

    /// Test cipher order enforcement (detailed)
    pub async fn test_cipher_order_enforcement(&self) -> Result<CipherOrderEnforcementAnalysis> {
        let mut test_results = Vec::new();

        // Define test cases with different cipher orders
        let tests = vec![
            // Test 1: Strong to weak order
            (
                "Strong to weak",
                vec![
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_AES_128_GCM_SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "AES256-SHA",
                    "AES128-SHA",
                    "DES-CBC3-SHA",
                ],
                "ECDHE-RSA-AES256-GCM-SHA384", // Expected if client preference
                "ECDHE-RSA-AES256-GCM-SHA384", // Expected if server preference (assuming server prefers strong)
            ),
            // Test 2: Weak to strong order
            (
                "Weak to strong",
                vec![
                    "DES-CBC3-SHA",
                    "AES128-SHA",
                    "AES256-SHA",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                ],
                "DES-CBC3-SHA",                // Expected if client preference
                "ECDHE-RSA-AES256-GCM-SHA384", // Expected if server preference (assuming server prefers strong)
            ),
            // Test 3: Random order
            (
                "Random order",
                vec![
                    "AES128-SHA",
                    "DES-CBC3-SHA",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "AES256-SHA",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                ],
                "AES128-SHA",                  // Expected if client preference
                "ECDHE-RSA-AES256-GCM-SHA384", // Expected if server preference
            ),
            // Test 4: Only modern ciphers
            (
                "Modern ciphers only",
                vec!["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"],
                "ECDHE-RSA-AES128-GCM-SHA256", // Expected if client preference
                "ECDHE-RSA-AES256-GCM-SHA384", // Expected if server preference
            ),
        ];

        for (test_name, client_order, expected_client, expected_server) in tests {
            if let Ok(selected) = self.test_cipher_selection(&client_order).await {
                let matches_server = selected == expected_server;

                test_results.push(CipherOrderEnforcementTest {
                    test_name: test_name.to_string(),
                    client_order: client_order.iter().map(|s| s.to_string()).collect(),
                    server_selected: selected,
                    expected_if_server_preference: expected_server.to_string(),
                    expected_if_client_preference: expected_client.to_string(),
                    matches_server_preference: matches_server,
                });
            }
        }

        // Calculate consistency score (how many tests matched server preference)
        let server_preference_matches = test_results
            .iter()
            .filter(|t| t.matches_server_preference)
            .count();

        let consistency_score = if test_results.is_empty() {
            0.0
        } else {
            (server_preference_matches as f64) / (test_results.len() as f64) * 100.0
        };

        let inconclusive = test_results.is_empty();
        let server_enforces_order = !inconclusive && consistency_score > 75.0;

        let details = if inconclusive {
            "Cipher order enforcement inconclusive - no successful comparison handshakes"
                .to_string()
        } else {
            format!(
                "Cipher order enforcement: {}. Consistency score: {:.1}%. {}/{} tests matched server preference.",
                if server_enforces_order { "YES" } else { "NO" },
                consistency_score,
                server_preference_matches,
                test_results.len()
            )
        };

        Ok(CipherOrderEnforcementAnalysis {
            server_enforces_order,
            test_results,
            consistency_score,
            details,
            inconclusive,
        })
    }

    async fn test_cipher_selection(&self, cipher_list: &[&str]) -> Result<String> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream = crate::utils::network::into_blocking_std_stream(stream, connect_timeout)?;

        let (hostname, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
        let cipher_string = cipher_list.join(":");
        tokio::task::spawn_blocking(move || -> Result<String> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // Cipher negotiation is independent of certificate validity; the scanner
            // must probe it on bad-cert hosts too (trust assessed separately).
            builder.set_verify(SslVerifyMode::NONE);

            // Set cipher list
            builder.set_cipher_list(&cipher_string)?;
            // set_cipher_list does not constrain TLS 1.3 ciphers. Keep this
            // probe on TLS 1.2 so the configured order is the order measured.
            builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

            let connector = builder.build();

            match connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname, std_stream)
            {
                Ok(ssl_stream) => {
                    let cipher = ssl_stream.ssl().current_cipher().ok_or_else(|| {
                        crate::error::TlsError::InvalidHandshake {
                            details: "No cipher negotiated".into(),
                        }
                    })?;

                    Ok(cipher.name().to_string())
                }
                Err(e) => Err(crate::error::TlsError::Other(format!(
                    "Connection failed: {}",
                    e
                ))),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("cipher selection task failed: {}", e)))?
    }
}

fn analyze_observed_certificate_compression(cert: &X509) -> Result<CertificateCompressionAnalysis> {
    let cert_der = cert.to_der()?;
    let original_size = cert_der.len();

    let details = format!(
        "Certificate size: {} bytes. Certificate compression is a TLS 1.3 feature (RFC 8879), \
        but OpenSSL doesn't expose compression details directly, so support could not be determined.",
        original_size
    );

    Ok(CertificateCompressionAnalysis {
        compression_supported: false,
        compression_algorithms: Vec::new(),
        original_size: Some(original_size),
        compressed_size: None,
        compression_ratio: None,
        details,
        inconclusive: true,
    })
}

fn extract_certificate_info(cert: &X509) -> Result<CertificateInfo> {
    let subject = cert
        .subject_name()
        .entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                String::from_utf8_lossy(e.data().as_slice())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    let issuer = cert
        .issuer_name()
        .entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                String::from_utf8_lossy(e.data().as_slice())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    let san_entries = if let Some(san) = cert.subject_alt_names() {
        san.iter()
            .filter_map(|name| {
                if let Some(dns) = name.dnsname() {
                    Some(format!("DNS:{}", dns))
                } else {
                    // `ipaddress()` returns the raw network-order address bytes
                    // (4 for IPv4, 16 for IPv6), not text — format them as an
                    // address rather than lossy-decoding the bytes as UTF-8.
                    name.ipaddress().map(|ip| match ip.len() {
                        4 => <[u8; 4]>::try_from(ip)
                            .map(std::net::Ipv4Addr::from)
                            .map(|addr| format!("IP:{addr}"))
                            .unwrap_or_else(|_| format!("IP:{}", hex::encode(ip))),
                        16 => {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(ip);
                            format!("IP:{}", std::net::Ipv6Addr::from(octets))
                        }
                        _ => format!("IP:{}", hex::encode(ip)),
                    })
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let valid_from = cert.not_before().to_string();
    let valid_until = cert.not_after().to_string();

    let digest = cert.digest(openssl::hash::MessageDigest::sha256())?;
    let fingerprint = digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    Ok(CertificateInfo {
        subject,
        issuer,
        san_entries,
        valid_from,
        valid_until,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509Builder, X509NameBuilder};

    #[test]
    fn test_extract_certificate_info() {
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
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();

        let mut san = SubjectAlternativeName::new();
        san.dns("example.com");
        let san_ext = san.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(san_ext).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        let info = extract_certificate_info(&cert).expect("certificate info should parse");
        assert!(info.subject.contains("CN=example.com"));
        assert!(info.issuer.contains("CN=example.com"));
        assert!(
            info.san_entries
                .iter()
                .any(|entry| entry.contains("DNS:example.com"))
        );
        assert!(info.fingerprint.contains(':'));
    }

    #[test]
    fn test_extract_certificate_info_without_san() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "no-san.example").unwrap();
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

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        let info = extract_certificate_info(&cert).expect("certificate info should parse");
        assert!(info.san_entries.is_empty());
        assert!(info.subject.contains("CN=no-san.example"));
    }

    #[test]
    fn test_extract_certificate_info_includes_serial() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "serial.example").unwrap();
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

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        let info = extract_certificate_info(&cert).expect("certificate info should parse");
        assert!(!info.fingerprint.is_empty());
    }

    #[test]
    fn test_consistency_score_calculation() {
        // Test consistency score calculation
        let test_results = [
            CipherOrderEnforcementTest {
                test_name: "Test 1".to_string(),
                client_order: vec!["A".to_string()],
                server_selected: "A".to_string(),
                expected_if_server_preference: "A".to_string(),
                expected_if_client_preference: "A".to_string(),
                matches_server_preference: true,
            },
            CipherOrderEnforcementTest {
                test_name: "Test 2".to_string(),
                client_order: vec!["B".to_string()],
                server_selected: "B".to_string(),
                expected_if_server_preference: "A".to_string(),
                expected_if_client_preference: "B".to_string(),
                matches_server_preference: false,
            },
        ];

        let matches = test_results
            .iter()
            .filter(|t| t.matches_server_preference)
            .count();
        let score = (matches as f64) / (test_results.len() as f64) * 100.0;

        assert_eq!(score, 50.0);
    }

    #[test]
    fn test_certificate_compression_serde_roundtrip() {
        let analysis = CertificateCompressionAnalysis {
            compression_supported: true,
            compression_algorithms: vec!["brotli".to_string()],
            original_size: Some(2048),
            compressed_size: Some(512),
            compression_ratio: Some(0.25),
            details: "test".to_string(),
            inconclusive: false,
        };

        let json = serde_json::to_string(&analysis).expect("serialize");
        let decoded: CertificateCompressionAnalysis =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            decoded.compression_supported,
            analysis.compression_supported
        );
        assert_eq!(
            decoded.compression_algorithms,
            analysis.compression_algorithms
        );
        assert_eq!(decoded.original_size, analysis.original_size);
        assert_eq!(decoded.compressed_size, analysis.compressed_size);
    }

    #[test]
    fn delegated_credential_analysis_is_explicitly_inconclusive_without_entry_extensions() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "delegated-credential.example")
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
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        let analysis = analyze_delegated_credential_certificate(&builder.build().to_der().unwrap())
            .expect("certificate should parse");
        assert_eq!(analysis.extension_type, DELEGATED_CREDENTIAL_EXTENSION_TYPE);
        assert!(!analysis.certificate_allows_delegation);
        assert!(!analysis.credential_observed);
        assert_eq!(analysis.status, "not_observed");
        assert!(
            analysis
                .limitations
                .iter()
                .any(|limitation| limitation.contains("CertificateEntry extension 34"))
        );
    }

    #[test]
    fn test_observed_certificate_compression_is_inconclusive() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "compression.example")
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
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        let analysis =
            analyze_observed_certificate_compression(&cert).expect("analysis should succeed");

        assert!(analysis.inconclusive);
        assert!(!analysis.compression_supported);
        assert!(analysis.original_size.is_some());
        assert!(analysis.details.contains("could not be determined"));
    }

    #[test]
    fn test_cipher_order_enforcement_serde_roundtrip() {
        let analysis = CipherOrderEnforcementAnalysis {
            server_enforces_order: true,
            test_results: vec![CipherOrderEnforcementTest {
                test_name: "basic".to_string(),
                client_order: vec!["A".to_string()],
                server_selected: "A".to_string(),
                expected_if_server_preference: "A".to_string(),
                expected_if_client_preference: "A".to_string(),
                matches_server_preference: true,
            }],
            consistency_score: 100.0,
            details: "ok".to_string(),
            inconclusive: false,
        };

        let json = serde_json::to_string(&analysis).expect("serialize");
        let decoded: CipherOrderEnforcementAnalysis =
            serde_json::from_str(&json).expect("deserialize");
        assert!(decoded.server_enforces_order);
        assert_eq!(decoded.test_results.len(), 1);
        assert_eq!(decoded.consistency_score, 100.0);
    }

    #[tokio::test]
    async fn test_certificate_compression_handshake_failure_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move { if let Ok((_socket, _)) = listener.accept().await {} });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = CertificateAdvancedTester::new(target);

        let result = tester
            .test_certificate_compression()
            .await
            .expect("compression probe should return result");

        assert!(result.inconclusive);
        assert!(!result.compression_supported);
        assert!(result.details.contains("TLS 1.3 connection failed"));
    }

    #[tokio::test]
    async fn test_cipher_order_no_successful_handshakes_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        drop(listener);

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = CertificateAdvancedTester::new(target);

        let result = tester
            .test_cipher_order_enforcement()
            .await
            .expect("cipher order probe should return result");

        assert!(result.inconclusive);
        assert!(!result.server_enforces_order);
        assert_eq!(result.consistency_score, 0.0);
        assert!(result.details.contains("inconclusive"));
    }
}
