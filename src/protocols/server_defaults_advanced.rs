// Advanced Server Defaults Analysis
// Cipher order preference, DH parameter analysis, ECDH curves, Key exchange details

mod analysis;
mod model;

pub use model::{
    CipherOrderPreference, CipherOrderTest, DhParameterAnalysis, DhStrength, EcdhCurvesAnalysis,
    KeyExchangeAnalysis, KeyExchangeParams,
};

use crate::utils::network::Target;
use crate::{Result, tls_bail};
use analysis::{analyze_cipher_kex, classify_dh_strength, estimate_dh_size, estimate_key_size};
use openssl::ssl::{SslConnector, SslMethod};
use tokio::time::Duration;

/// Server defaults advanced tester
pub struct ServerDefaultsAdvancedTester {
    target: Target,
}

impl ServerDefaultsAdvancedTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test cipher order preference in detail
    pub async fn test_cipher_order_preference(&self) -> Result<CipherOrderPreference> {
        let mut test_results = Vec::new();

        let test1_client_order = vec![
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
        ];

        if let Ok(selected) = self.test_with_cipher_list(&test1_client_order).await {
            test_results.push(CipherOrderTest {
                client_preference: test1_client_order.iter().map(|s| s.to_string()).collect(),
                server_selected: selected.clone(),
                matched_client_first: selected == test1_client_order[0],
            });
        }

        let test2_client_order = vec![
            "DES-CBC3-SHA",
            "AES128-SHA",
            "AES256-SHA",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ];

        if let Ok(selected) = self.test_with_cipher_list(&test2_client_order).await {
            test_results.push(CipherOrderTest {
                client_preference: test2_client_order.iter().map(|s| s.to_string()).collect(),
                server_selected: selected.clone(),
                matched_client_first: selected == test2_client_order[0],
            });
        }

        let test3_client_order = vec![
            "AES128-SHA",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AES256-SHA",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ];

        if let Ok(selected) = self.test_with_cipher_list(&test3_client_order).await {
            test_results.push(CipherOrderTest {
                client_preference: test3_client_order.iter().map(|s| s.to_string()).collect(),
                server_selected: selected.clone(),
                matched_client_first: selected == test3_client_order[0],
            });
        }

        let client_respected_count = test_results
            .iter()
            .filter(|test| test.matched_client_first)
            .count();
        let inconclusive = test_results.is_empty();
        let server_preferred = !inconclusive && client_respected_count == 0;
        let client_order_respected = !inconclusive && client_respected_count == test_results.len();

        let details = if inconclusive {
            "Cipher order preference inconclusive (no successful comparison handshakes)".to_string()
        } else if server_preferred {
            format!(
                "Server enforces its own cipher preference (0/{} tests matched client's first choice)",
                test_results.len()
            )
        } else if client_order_respected {
            format!(
                "Server respects client cipher preference ({}/{} tests matched client's first choice)",
                client_respected_count,
                test_results.len()
            )
        } else {
            format!(
                "Mixed behavior: {}/{} tests matched client's first choice",
                client_respected_count,
                test_results.len()
            )
        };

        Ok(CipherOrderPreference {
            server_preferred,
            client_order_respected,
            inconclusive,
            test_results,
            details,
        })
    }

    async fn test_with_cipher_list(&self, cipher_list: &[&str]) -> Result<String> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let handshake_timeout = Duration::from_secs(2);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, handshake_timeout)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list(&cipher_list.join(":"))?;

        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream.ssl().current_cipher().ok_or_else(|| {
            crate::error::TlsError::InvalidHandshake {
                details: "No cipher negotiated".into(),
            }
        })?;

        Ok(cipher.name().to_string())
    }

    /// Analyze DH parameter strength
    pub async fn analyze_dh_parameters(&self) -> Result<DhParameterAnalysis> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let handshake_timeout = Duration::from_secs(2);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, handshake_timeout)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list("DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA")?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                    let cipher_name = cipher.name();

                    if cipher_name.contains("DHE") || cipher_name.contains("EDH") {
                        let estimated_size = estimate_dh_size(cipher_name);
                        let strength = classify_dh_strength(estimated_size);

                        let details = format!(
                            "DH cipher negotiated: {} (estimated DH parameter size: {} bits)",
                            cipher_name, estimated_size
                        );

                        return Ok(DhParameterAnalysis {
                            dh_supported: true,
                            dh_size_bits: Some(estimated_size),
                            dh_prime: None,
                            generator: None,
                            strength,
                            details,
                        });
                    }
                }

                Ok(DhParameterAnalysis {
                    dh_supported: false,
                    dh_size_bits: None,
                    dh_prime: None,
                    generator: None,
                    strength: DhStrength::Weak,
                    details: "DH ciphers not supported or not negotiated".to_string(),
                })
            }
            Err(error) => Ok(DhParameterAnalysis {
                dh_supported: false,
                dh_size_bits: None,
                dh_prime: None,
                generator: None,
                strength: DhStrength::Weak,
                details: format!("DH connection failed: {}", error),
            }),
        }
    }

    /// Analyze ECDH curves preference
    pub async fn analyze_ecdh_curves(&self) -> Result<EcdhCurvesAnalysis> {
        let curves_to_test = [
            ("X25519", "X25519"),
            ("P-256", "P-256"),
            ("P-384", "P-384"),
            ("P-521", "P-521"),
        ];

        let mut supported_curves = Vec::new();

        for (display_name, group_name) in curves_to_test {
            if self.test_ecdh_curve(group_name).await.is_ok() {
                supported_curves.push(display_name.to_string());
            }
        }

        let preferred_curve = if supported_curves.len() == 1 {
            supported_curves.first().cloned()
        } else {
            None
        };
        let ecdh_supported = !supported_curves.is_empty();
        let server_enforces_preference = false;
        let preference_measured = false;

        let details = if ecdh_supported {
            if let Some(curve) = preferred_curve.as_deref() {
                format!(
                    "ECDH supported for curve {}. Additional curve preference was not measured directly. Supported curves: {}",
                    curve,
                    supported_curves.join(", ")
                )
            } else {
                format!(
                    "ECDH supported for at least one configured curve. Curve preference was not measured directly. Supported curves: {}",
                    supported_curves.join(", ")
                )
            }
        } else {
            "ECDH not supported or no configured curve could be negotiated".to_string()
        };

        Ok(EcdhCurvesAnalysis {
            ecdh_supported,
            preferred_curve,
            supported_curves,
            server_enforces_preference,
            preference_measured,
            details,
        })
    }

    async fn test_ecdh_curve(&self, group_name: &str) -> Result<()> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let handshake_timeout = Duration::from_secs(2);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, handshake_timeout)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")?;
        builder.set_groups_list(group_name)?;

        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream
            .ssl()
            .current_cipher()
            .ok_or_else(|| crate::error::TlsError::Other("No cipher negotiated".to_string()))?;

        if cipher.name().contains("ECDHE") {
            Ok(())
        } else {
            tls_bail!("ECDHE not negotiated")
        }
    }

    /// Analyze key exchange in detail
    pub async fn analyze_key_exchange(&self) -> Result<KeyExchangeAnalysis> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let handshake_timeout = Duration::from_secs(2);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, handshake_timeout)?;

        let builder = SslConnector::builder(SslMethod::tls())?;
        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream.ssl().current_cipher().ok_or_else(|| {
            crate::error::TlsError::InvalidHandshake {
                details: "No cipher negotiated".into(),
            }
        })?;

        let cipher_name = cipher.name().to_string();
        let (algorithm, ephemeral, parameters) = analyze_cipher_kex(&cipher_name);
        let key_size = estimate_key_size(&parameters);
        let reuse_detection_measured = false;
        let reuse_detected = false;

        let details = format!(
            "Algorithm: {}, Ephemeral: {}, Key size: {} bits, Reuse detected: {}. Ephemeral key reuse was not measured directly.",
            algorithm,
            ephemeral,
            key_size.unwrap_or(0),
            reuse_detected
        );

        Ok(KeyExchangeAnalysis {
            algorithm,
            ephemeral,
            key_size,
            parameters,
            reuse_detected,
            reuse_detection_measured,
            details,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Once;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn test_classify_dh_strength() {
        assert_eq!(classify_dh_strength(512), DhStrength::Weak);
        assert_eq!(classify_dh_strength(1024), DhStrength::Moderate);
        assert_eq!(classify_dh_strength(2048), DhStrength::Strong);
        assert_eq!(classify_dh_strength(4096), DhStrength::VeryStrong);
    }

    #[test]
    fn test_analyze_cipher_kex() {
        let (algo, ephemeral, _) = analyze_cipher_kex("ECDHE-RSA-AES256-GCM-SHA384");
        assert_eq!(algo, "ECDHE");
        assert!(ephemeral);

        let (algo, ephemeral, _) = analyze_cipher_kex("DHE-RSA-AES128-SHA");
        assert_eq!(algo, "DHE");
        assert!(ephemeral);

        let (algo, ephemeral, _) = analyze_cipher_kex("AES256-SHA");
        assert_eq!(algo, "RSA");
        assert!(!ephemeral);
    }

    #[test]
    fn test_estimate_key_size() {
        let rsa = estimate_key_size(&KeyExchangeParams::Rsa { modulus_size: 2048 });
        assert_eq!(rsa, Some(2048));

        let dhe = estimate_key_size(&KeyExchangeParams::Dhe {
            prime_size: 3072,
            generator: 2,
        });
        assert_eq!(dhe, Some(3072));

        let ecdhe = estimate_key_size(&KeyExchangeParams::Ecdhe {
            curve: "P-256".to_string(),
            point_size: 256,
        });
        assert_eq!(ecdhe, Some(256));

        let unknown = estimate_key_size(&KeyExchangeParams::Unknown);
        assert_eq!(unknown, None);
    }

    #[test]
    fn test_estimate_dh_size() {
        assert_eq!(estimate_dh_size("DHE-RSA-AES256-SHA"), 2048);
        assert_eq!(estimate_dh_size("EDH-RSA-DES-CBC3-SHA"), 1024);
    }

    #[test]
    fn test_analyze_cipher_kex_unknown() {
        let (algo, ephemeral, params) = analyze_cipher_kex("UNKNOWN-CIPHER");
        assert_eq!(algo, "Unknown");
        assert!(!ephemeral);
        assert!(matches!(params, KeyExchangeParams::Unknown));
    }

    #[test]
    fn test_analyze_cipher_kex_ecdhe() {
        let (algo, ephemeral, _params) = analyze_cipher_kex("ECDHE-ECDSA-AES128-GCM-SHA256");
        assert_eq!(algo, "ECDHE");
        assert!(ephemeral);
    }

    #[test]
    fn test_analyze_cipher_kex_is_case_insensitive() {
        let (algo, ephemeral, params) = analyze_cipher_kex("ecdhe-rsa-aes256-gcm-sha384");
        assert_eq!(algo, "ECDHE");
        assert!(ephemeral);
        assert!(matches!(params, KeyExchangeParams::Ecdhe { .. }));
    }

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    async fn spawn_tls_server(max_accepts: usize) -> (SocketAddr, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tmp = std::env::temp_dir();
        let cert_path = tmp.join(format!(
            "cipherrun_test_cert_defaults_{}_{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();

        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(250),
                        acceptor.accept(stream),
                    )
                    .await;
                }
                remaining -= 1;
            }
        });

        (addr, cert_path)
    }

    #[tokio::test]
    async fn test_cipher_order_preference_no_matches() {
        install_crypto_provider();
        let (addr, cert_path) = spawn_tls_server(10).await;

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = ServerDefaultsAdvancedTester::new(target);

        let result = tester.test_cipher_order_preference().await.unwrap();
        assert!(result.inconclusive);
        assert!(!result.server_preferred);
        assert!(!result.client_order_respected);
        assert!(result.details.contains("inconclusive"));

        let _ = std::fs::remove_file(cert_path);
    }

    #[tokio::test]
    async fn test_dh_and_ecdh_analysis_on_local_tls() {
        install_crypto_provider();
        let (addr, cert_path) = spawn_tls_server(10).await;

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = ServerDefaultsAdvancedTester::new(target);

        let dh = tester.analyze_dh_parameters().await.unwrap();
        assert!(!dh.dh_supported);
        assert_eq!(dh.strength, DhStrength::Weak);
        assert!(dh.details.contains("DH"));

        let ecdh = tester.analyze_ecdh_curves().await.unwrap();
        assert!(!ecdh.ecdh_supported);
        assert!(!ecdh.preference_measured);
        assert!(ecdh.details.contains("ECDH"));

        let _ = std::fs::remove_file(cert_path);
    }

    #[tokio::test]
    async fn test_analyze_key_exchange_on_local_tls() {
        install_crypto_provider();
        let (addr, cert_path) = spawn_tls_server(6).await;

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = ServerDefaultsAdvancedTester::new(target);

        let result = tester.analyze_key_exchange().await;
        assert!(result.is_err());

        let _ = std::fs::remove_file(cert_path);
    }
}
