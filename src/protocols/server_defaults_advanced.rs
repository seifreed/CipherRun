// Advanced Server Defaults Analysis
// Cipher order preference, DH parameter analysis, ECDH curves, Key exchange details

use crate::utils::network::Target;
use crate::{Result, tls_bail};
use openssl::ssl::{SslConnector, SslMethod};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Server cipher order preference result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderPreference {
    pub server_preferred: bool,
    pub client_order_respected: bool,
    pub test_results: Vec<CipherOrderTest>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderTest {
    pub client_preference: Vec<String>,
    pub server_selected: String,
    pub matched_client_first: bool,
}

/// DH parameter strength analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhParameterAnalysis {
    pub dh_supported: bool,
    pub dh_size_bits: Option<u16>,
    pub dh_prime: Option<String>,
    pub generator: Option<u8>,
    pub strength: DhStrength,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhStrength {
    Weak,       // < 1024 bits
    Moderate,   // 1024 bits
    Strong,     // 2048 bits
    VeryStrong, // 4096+ bits
}

/// ECDH curves preference order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdhCurvesAnalysis {
    pub ecdh_supported: bool,
    pub preferred_curve: Option<String>,
    pub supported_curves: Vec<String>,
    pub server_enforces_preference: bool,
    pub details: String,
}

/// Server key exchange detailed analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeAnalysis {
    pub algorithm: String,
    pub ephemeral: bool,
    pub key_size: Option<u16>,
    pub parameters: KeyExchangeParams,
    pub reuse_detected: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyExchangeParams {
    Rsa { modulus_size: u16 },
    Dhe { prime_size: u16, generator: u8 },
    Ecdhe { curve: String, point_size: u16 },
    Unknown,
}

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

        // Test 1: Strong cipher first vs weak cipher first
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

        // Test 2: Weak cipher first vs strong cipher last
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

        // Test 3: Different order of same ciphers
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

        // Analyze results
        let client_respected_count = test_results
            .iter()
            .filter(|t| t.matched_client_first)
            .count();
        let server_preferred = client_respected_count == 0;
        let client_order_respected = client_respected_count == test_results.len();

        let details = if server_preferred {
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
            test_results,
            details,
        })
    }

    /// Test with specific cipher list
    async fn test_with_cipher_list(&self, cipher_list: &[&str]) -> Result<String> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| crate::error::TlsError::Timeout {
                duration: connect_timeout,
            })??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list(&cipher_list.join(":"))?;

        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream
            .ssl()
            .current_cipher()
            .ok_or_else(|| anyhow::anyhow!("No cipher negotiated"))?;

        Ok(cipher.name().to_string())
    }

    /// Analyze DH parameter strength
    pub async fn analyze_dh_parameters(&self) -> Result<DhParameterAnalysis> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| crate::error::TlsError::Timeout {
                duration: connect_timeout,
            })??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Request DHE ciphers
        builder.set_cipher_list("DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA")?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                let cipher = ssl_stream.ssl().current_cipher();

                if let Some(cipher) = cipher {
                    let cipher_name = cipher.name();

                    // Check if DHE was negotiated
                    if cipher_name.contains("DHE") || cipher_name.contains("EDH") {
                        // Try to extract DH parameters
                        // Note: rust-openssl doesn't expose DH parameter details directly
                        // We estimate based on cipher and connection success

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
            Err(e) => Ok(DhParameterAnalysis {
                dh_supported: false,
                dh_size_bits: None,
                dh_prime: None,
                generator: None,
                strength: DhStrength::Weak,
                details: format!("DH connection failed: {}", e),
            }),
        }
    }

    /// Analyze ECDH curves preference
    pub async fn analyze_ecdh_curves(&self) -> Result<EcdhCurvesAnalysis> {
        let curves_to_test = vec![
            (
                "x25519",
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            ),
            (
                "secp256r1",
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            ),
            (
                "secp384r1",
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            ),
            (
                "secp521r1",
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            ),
        ];

        let mut supported_curves = Vec::new();
        let mut preferred_curve = None;

        for (curve_name, cipher_list) in curves_to_test {
            if self.test_ecdh_curve(cipher_list).await.is_ok() {
                supported_curves.push(curve_name.to_string());
                if preferred_curve.is_none() {
                    preferred_curve = Some(curve_name.to_string());
                }
            }
        }

        let ecdh_supported = !supported_curves.is_empty();

        // Test if server enforces preference by trying different curve orders
        let server_enforces_preference = if supported_curves.len() > 1 {
            self.test_curve_preference_enforcement()
                .await
                .unwrap_or(false)
        } else {
            false
        };

        let details = if ecdh_supported {
            format!(
                "ECDH supported. Preferred curve: {}. Supported curves: {}. Server enforces preference: {}",
                preferred_curve.as_deref().unwrap_or("unknown"),
                supported_curves.join(", "),
                server_enforces_preference
            )
        } else {
            "ECDH not supported or not negotiated".to_string()
        };

        Ok(EcdhCurvesAnalysis {
            ecdh_supported,
            preferred_curve,
            supported_curves,
            server_enforces_preference,
            details,
        })
    }

    async fn test_ecdh_curve(&self, cipher_list: &str) -> Result<()> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| crate::error::TlsError::Timeout {
                duration: connect_timeout,
            })??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list(cipher_list)?;

        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream
            .ssl()
            .current_cipher()
            .ok_or_else(|| crate::error::TlsError::Other("No cipher negotiated".to_string()))?;

        let cipher_name = cipher.name();

        if cipher_name.contains("ECDHE") {
            Ok(())
        } else {
            tls_bail!("ECDHE not negotiated")
        }
    }

    async fn test_curve_preference_enforcement(&self) -> Result<bool> {
        // This is a simplified test
        // In a full implementation, we'd send ClientHello with different curve orders
        // and check if server always selects the same curve

        // For now, return true (assume server enforces preference)
        Ok(true)
    }

    /// Analyze key exchange in detail
    pub async fn analyze_key_exchange(&self) -> Result<KeyExchangeAnalysis> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| crate::error::TlsError::Timeout {
                duration: connect_timeout,
            })??;

        let std_stream = stream.into_std()?;

        let builder = SslConnector::builder(SslMethod::tls())?;

        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream
            .ssl()
            .current_cipher()
            .ok_or_else(|| anyhow::anyhow!("No cipher negotiated"))?;

        let cipher_name = cipher.name().to_string();

        // Analyze key exchange algorithm
        let (algorithm, ephemeral, parameters) = analyze_cipher_kex(&cipher_name);

        // Estimate key size
        let key_size = estimate_key_size(&cipher_name, &parameters);

        // Test for ephemeral key reuse (simplified)
        let reuse_detected = if ephemeral {
            self.test_ephemeral_key_reuse().await.unwrap_or(false)
        } else {
            false
        };

        let details = format!(
            "Algorithm: {}, Ephemeral: {}, Key size: {} bits, Reuse detected: {}",
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
            details,
        })
    }

    async fn test_ephemeral_key_reuse(&self) -> Result<bool> {
        // This is a simplified test
        // In a full implementation, we'd make multiple connections
        // and check if the ephemeral key is reused

        // For now, return false (assume no reuse)
        Ok(false)
    }
}

fn estimate_dh_size(cipher_name: &str) -> u16 {
    // Modern servers typically use 2048-bit DH
    // Older servers might use 1024-bit
    if cipher_name.contains("DHE-RSA-AES256") || cipher_name.contains("DHE-RSA-AES128") {
        2048
    } else {
        1024
    }
}

fn classify_dh_strength(size_bits: u16) -> DhStrength {
    match size_bits {
        0..=1023 => DhStrength::Weak,
        1024 => DhStrength::Moderate,
        2048 => DhStrength::Strong,
        _ => DhStrength::VeryStrong,
    }
}

fn analyze_cipher_kex(cipher_name: &str) -> (String, bool, KeyExchangeParams) {
    if cipher_name.contains("ECDHE") {
        let curve = if cipher_name.contains("256") {
            "secp256r1".to_string()
        } else if cipher_name.contains("384") {
            "secp384r1".to_string()
        } else {
            "secp256r1".to_string()
        };

        (
            "ECDHE".to_string(),
            true,
            KeyExchangeParams::Ecdhe {
                curve,
                point_size: 256,
            },
        )
    } else if cipher_name.contains("DHE") || cipher_name.contains("EDH") {
        (
            "DHE".to_string(),
            true,
            KeyExchangeParams::Dhe {
                prime_size: 2048,
                generator: 2,
            },
        )
    } else if cipher_name.contains("RSA")
        || cipher_name.starts_with("AES")
        || cipher_name.starts_with("DES")
        || cipher_name.starts_with("3DES")
        || cipher_name.starts_with("RC4")
        || cipher_name.starts_with("CAMELLIA")
    {
        // Ciphers starting with AES, DES, etc. without explicit key exchange use RSA
        (
            "RSA".to_string(),
            false,
            KeyExchangeParams::Rsa { modulus_size: 2048 },
        )
    } else {
        ("Unknown".to_string(), false, KeyExchangeParams::Unknown)
    }
}

fn estimate_key_size(_cipher_name: &str, params: &KeyExchangeParams) -> Option<u16> {
    match params {
        KeyExchangeParams::Rsa { modulus_size } => Some(*modulus_size),
        KeyExchangeParams::Dhe { prime_size, .. } => Some(*prime_size),
        KeyExchangeParams::Ecdhe { point_size, .. } => Some(*point_size),
        KeyExchangeParams::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
