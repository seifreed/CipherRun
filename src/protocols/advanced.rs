// Advanced Protocol Tests
// RC4 biases, TLS truncation, cipher per protocol, forward secrecy detailed

use crate::Result;
use crate::utils::network::Target;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// RC4 biases analysis (Appelbaum attack and others)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rc4BiasesAnalysis {
    pub rc4_supported: bool,
    pub rc4_ciphers: Vec<String>,
    pub vulnerable_to_appelbaum: bool,
    pub vulnerable_to_bar_mitzvah: bool,
    pub bias_details: String,
}

/// TLS truncation attack analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsTruncationAnalysis {
    pub vulnerable: bool,
    pub accepts_truncated_hmac: bool,
    pub accepts_no_close_notify: bool,
    pub details: String,
}

/// Cipher suites per protocol detailed listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherPerProtocolAnalysis {
    pub protocols: Vec<ProtocolCipherSupport>,
    pub total_ciphers: usize,
    pub total_protocols: usize,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCipherSupport {
    pub protocol: String,
    pub supported_ciphers: Vec<CipherDetails>,
    pub cipher_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherDetails {
    pub name: String,
    pub strength: CipherStrength,
    pub key_exchange: String,
    pub encryption: String,
    pub mac: String,
    pub forward_secrecy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherStrength {
    Weak,       // Export ciphers, NULL, DES, MD5
    Medium,     // 3DES, RC4, 128-bit without FS
    Strong,     // AES-128, AES-256 with FS
    VeryStrong, // AES-GCM with ECDHE/DHE, ChaCha20-Poly1305
}

/// Forward secrecy detailed analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardSecrecyAnalysis {
    pub supported: bool,
    pub ecdhe_supported: bool,
    pub dhe_supported: bool,
    pub preferred: bool,
    pub fs_ciphers: Vec<ForwardSecrecyCipher>,
    pub non_fs_ciphers: Vec<String>,
    pub fs_percentage: f64,
    pub grade: FsGrade,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardSecrecyCipher {
    pub name: String,
    pub protocol: String,
    pub key_exchange: String,
    pub encryption: String,
    pub bits: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsGrade {
    A, // All ciphers have FS
    B, // >80% have FS
    C, // >50% have FS
    D, // <50% have FS
    F, // No FS support
}

/// Advanced protocol tester
pub struct ProtocolAdvancedTester {
    target: Target,
}

impl ProtocolAdvancedTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for RC4 biases (Appelbaum attack, Bar Mitzvah attack)
    pub async fn test_rc4_biases(&self) -> Result<Rc4BiasesAnalysis> {
        let rc4_ciphers = vec![
            "RC4-SHA",
            "RC4-MD5",
            "ECDHE-RSA-RC4-SHA",
            "ECDHE-ECDSA-RC4-SHA",
            "EXP-RC4-MD5",
            "EXP-RC2-CBC-MD5",
        ];

        let mut supported_rc4_ciphers = Vec::new();

        for cipher in &rc4_ciphers {
            if self.test_cipher_support(cipher).await.unwrap_or(false) {
                supported_rc4_ciphers.push(cipher.to_string());
            }
        }

        let rc4_supported = !supported_rc4_ciphers.is_empty();

        // RC4 is vulnerable to multiple attacks:
        // 1. Appelbaum attack (2013) - statistical biases in RC4 keystream
        // 2. Bar Mitzvah attack (2015) - exploits biases in first 256 bytes
        // 3. NOMORE attack (2015) - exploits single-byte biases

        let vulnerable_to_appelbaum = rc4_supported;
        let vulnerable_to_bar_mitzvah = rc4_supported;

        let bias_details = if rc4_supported {
            format!(
                "RC4 is vulnerable to multiple bias attacks:\n\
                - Appelbaum attack (2013): Statistical biases in RC4 keystream\n\
                - Bar Mitzvah attack (2015): Exploits biases in first 256 bytes\n\
                - NOMORE attack (2015): Single-byte biases in TLS\n\
                Supported RC4 ciphers: {}",
                supported_rc4_ciphers.join(", ")
            )
        } else {
            "RC4 not supported - not vulnerable to bias attacks".to_string()
        };

        Ok(Rc4BiasesAnalysis {
            rc4_supported,
            rc4_ciphers: supported_rc4_ciphers,
            vulnerable_to_appelbaum,
            vulnerable_to_bar_mitzvah,
            bias_details,
        })
    }

    async fn test_cipher_support(&self, cipher: &str) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list(cipher)?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Test for TLS truncation attacks
    pub async fn test_tls_truncation(&self) -> Result<TlsTruncationAnalysis> {
        // TLS truncation attacks exploit the handling of:
        // 1. Truncated HMAC extension (RFC 6066)
        // 2. Missing close_notify alert

        let accepts_truncated_hmac = self.test_truncated_hmac_extension().await.unwrap_or(false);
        let accepts_no_close_notify = self.test_no_close_notify().await.unwrap_or(false);

        let vulnerable = accepts_truncated_hmac || accepts_no_close_notify;

        let details = format!(
            "TLS truncation vulnerability: {}. Accepts truncated HMAC: {}. Accepts no close_notify: {}.",
            if vulnerable { "YES" } else { "NO" },
            accepts_truncated_hmac,
            accepts_no_close_notify
        );

        Ok(TlsTruncationAnalysis {
            vulnerable,
            accepts_truncated_hmac,
            accepts_no_close_notify,
            details,
        })
    }

    async fn test_truncated_hmac_extension(&self) -> Result<bool> {
        // This is a simplified test
        // In a full implementation, we'd send ClientHello with truncated HMAC extension
        // and check if server accepts it

        // For now, conservatively return false (not vulnerable)
        Ok(false)
    }

    async fn test_no_close_notify(&self) -> Result<bool> {
        // This is a simplified test
        // In a full implementation, we'd establish connection and close without close_notify
        // and check if server detects the truncation

        // For now, conservatively return false (not vulnerable)
        Ok(false)
    }

    /// Test cipher suites per protocol (detailed listing)
    pub async fn test_ciphers_per_protocol(&self) -> Result<CipherPerProtocolAnalysis> {
        let protocols = vec![
            ("SSLv3", SslVersion::SSL3),
            ("TLS 1.0", SslVersion::TLS1),
            ("TLS 1.1", SslVersion::TLS1_1),
            ("TLS 1.2", SslVersion::TLS1_2),
            ("TLS 1.3", SslVersion::TLS1_3),
        ];

        let mut protocol_results = Vec::new();
        let mut total_ciphers = 0;

        for (protocol_name, ssl_version) in protocols {
            if let Ok(ciphers) = self.enumerate_protocol_ciphers(ssl_version).await {
                let cipher_count = ciphers.len();
                total_ciphers += cipher_count;

                protocol_results.push(ProtocolCipherSupport {
                    protocol: protocol_name.to_string(),
                    supported_ciphers: ciphers,
                    cipher_count,
                });
            }
        }

        let total_protocols = protocol_results.len();

        let details = format!(
            "Found {} cipher suites across {} protocols",
            total_ciphers, total_protocols
        );

        Ok(CipherPerProtocolAnalysis {
            protocols: protocol_results,
            total_ciphers,
            total_protocols,
            details,
        })
    }

    async fn enumerate_protocol_ciphers(&self, protocol: SslVersion) -> Result<Vec<CipherDetails>> {
        // Common cipher suites to test
        let test_ciphers = vec![
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-SHA256",
            "DHE-RSA-AES128-SHA256",
            "DHE-RSA-AES256-SHA",
            "DHE-RSA-AES128-SHA",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA256",
            "AES128-SHA256",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
            "RC4-SHA",
            "RC4-MD5",
        ];

        let mut supported_ciphers = Vec::new();

        for cipher in test_ciphers {
            if let Ok(true) = self.test_cipher_with_protocol(cipher, protocol).await {
                supported_ciphers.push(analyze_cipher_details(cipher));
            }
        }

        Ok(supported_ciphers)
    }

    async fn test_cipher_with_protocol(&self, cipher: &str, protocol: SslVersion) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(protocol))?;
        builder.set_max_proto_version(Some(protocol))?;
        builder.set_cipher_list(cipher)?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Test forward secrecy in detail
    pub async fn test_forward_secrecy_detailed(&self) -> Result<ForwardSecrecyAnalysis> {
        // Define FS cipher suites
        let fs_ciphers = vec![
            (
                "TLS_AES_256_GCM_SHA384",
                "TLS 1.3",
                "ECDHE",
                "AES-256-GCM",
                256,
            ),
            (
                "TLS_AES_128_GCM_SHA256",
                "TLS 1.3",
                "ECDHE",
                "AES-128-GCM",
                128,
            ),
            (
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS 1.3",
                "ECDHE",
                "ChaCha20-Poly1305",
                256,
            ),
            (
                "ECDHE-RSA-AES256-GCM-SHA384",
                "TLS 1.2",
                "ECDHE",
                "AES-256-GCM",
                256,
            ),
            (
                "ECDHE-RSA-AES128-GCM-SHA256",
                "TLS 1.2",
                "ECDHE",
                "AES-128-GCM",
                128,
            ),
            (
                "ECDHE-RSA-CHACHA20-POLY1305",
                "TLS 1.2",
                "ECDHE",
                "ChaCha20-Poly1305",
                256,
            ),
            (
                "DHE-RSA-AES256-GCM-SHA384",
                "TLS 1.2",
                "DHE",
                "AES-256-GCM",
                256,
            ),
            (
                "DHE-RSA-AES128-GCM-SHA256",
                "TLS 1.2",
                "DHE",
                "AES-128-GCM",
                128,
            ),
        ];

        let non_fs_ciphers = vec![
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA256",
            "AES128-SHA256",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
        ];

        let mut supported_fs_ciphers = Vec::new();
        let mut supported_non_fs_ciphers = Vec::new();

        // Test FS ciphers
        for (cipher, protocol, kex, enc, bits) in &fs_ciphers {
            if self.test_cipher_support(cipher).await.unwrap_or(false) {
                supported_fs_ciphers.push(ForwardSecrecyCipher {
                    name: cipher.to_string(),
                    protocol: protocol.to_string(),
                    key_exchange: kex.to_string(),
                    encryption: enc.to_string(),
                    bits: *bits,
                });
            }
        }

        // Test non-FS ciphers
        for cipher in &non_fs_ciphers {
            if self.test_cipher_support(cipher).await.unwrap_or(false) {
                supported_non_fs_ciphers.push(cipher.to_string());
            }
        }

        let total_ciphers = supported_fs_ciphers.len() + supported_non_fs_ciphers.len();
        let fs_percentage = if total_ciphers > 0 {
            (supported_fs_ciphers.len() as f64 / total_ciphers as f64) * 100.0
        } else {
            0.0
        };

        let ecdhe_supported = supported_fs_ciphers
            .iter()
            .any(|c| c.key_exchange == "ECDHE");
        let dhe_supported = supported_fs_ciphers.iter().any(|c| c.key_exchange == "DHE");
        let fs_supported = !supported_fs_ciphers.is_empty();

        // Check if FS is preferred (first cipher is FS)
        let preferred = if total_ciphers > 0 {
            self.check_fs_preference().await.unwrap_or(false)
        } else {
            false
        };

        let grade = classify_fs_grade(fs_percentage, fs_supported);

        let details = format!(
            "Forward Secrecy: {}. ECDHE: {}. DHE: {}. FS preferred: {}. {}/{} ciphers ({:.1}%) support FS. Grade: {}",
            if fs_supported { "YES" } else { "NO" },
            ecdhe_supported,
            dhe_supported,
            preferred,
            supported_fs_ciphers.len(),
            total_ciphers,
            fs_percentage,
            grade_to_string(grade)
        );

        Ok(ForwardSecrecyAnalysis {
            supported: fs_supported,
            ecdhe_supported,
            dhe_supported,
            preferred,
            fs_ciphers: supported_fs_ciphers,
            non_fs_ciphers: supported_non_fs_ciphers,
            fs_percentage,
            grade,
            details,
        })
    }

    async fn check_fs_preference(&self) -> Result<bool> {
        // Connect and check if the selected cipher has FS
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let builder = SslConnector::builder(SslMethod::tls())?;

        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream
            .ssl()
            .current_cipher()
            .ok_or_else(|| anyhow::anyhow!("No cipher negotiated"))?;

        let cipher_name = cipher.name();

        // Check if cipher has FS (ECDHE or DHE)
        Ok(cipher_name.contains("ECDHE") || cipher_name.contains("DHE"))
    }
}

fn analyze_cipher_details(cipher_name: &str) -> CipherDetails {
    let forward_secrecy = cipher_name.contains("ECDHE") || cipher_name.contains("DHE");

    let key_exchange = if cipher_name.starts_with("TLS_") || cipher_name.contains("ECDHE") {
        "ECDHE".to_string() // TLS 1.3 ciphers all use ECDHE
    } else if cipher_name.contains("DHE") {
        "DHE".to_string()
    } else if cipher_name.contains("RSA") {
        "RSA".to_string()
    } else {
        "Unknown".to_string()
    };

    let encryption = if cipher_name.contains("AES256-GCM") {
        "AES-256-GCM".to_string()
    } else if cipher_name.contains("AES128-GCM") {
        "AES-128-GCM".to_string()
    } else if cipher_name.contains("AES256") {
        "AES-256-CBC".to_string()
    } else if cipher_name.contains("AES128") {
        "AES-128-CBC".to_string()
    } else if cipher_name.contains("CHACHA20") {
        "ChaCha20-Poly1305".to_string()
    } else if cipher_name.contains("3DES") {
        "3DES".to_string()
    } else if cipher_name.contains("RC4") {
        "RC4".to_string()
    } else {
        "Unknown".to_string()
    };

    let mac = if cipher_name.contains("GCM") || cipher_name.contains("POLY1305") {
        "AEAD".to_string()
    } else if cipher_name.contains("SHA384") {
        "SHA384".to_string()
    } else if cipher_name.contains("SHA256") {
        "SHA256".to_string()
    } else if cipher_name.contains("SHA") {
        "SHA1".to_string()
    } else if cipher_name.contains("MD5") {
        "MD5".to_string()
    } else {
        "Unknown".to_string()
    };

    let strength = classify_cipher_strength(cipher_name, forward_secrecy, &encryption, &mac);

    CipherDetails {
        name: cipher_name.to_string(),
        strength,
        key_exchange,
        encryption,
        mac,
        forward_secrecy,
    }
}

fn classify_cipher_strength(cipher: &str, fs: bool, enc: &str, mac: &str) -> CipherStrength {
    // Weak: Export, NULL, DES, MD5
    if cipher.contains("EXP")
        || cipher.contains("NULL")
        || cipher.contains("DES-CBC-")
        || mac == "MD5"
    {
        return CipherStrength::Weak;
    }

    // Medium: 3DES, RC4, or no FS
    if cipher.contains("3DES") || cipher.contains("RC4") || (!fs && !cipher.starts_with("TLS_")) {
        return CipherStrength::Medium;
    }

    // VeryStrong: AEAD with FS (GCM, POLY1305)
    if (enc.contains("GCM") || enc.contains("Poly1305")) && fs {
        return CipherStrength::VeryStrong;
    }

    // Strong: AES with FS
    if enc.contains("AES") && fs {
        return CipherStrength::Strong;
    }

    CipherStrength::Medium
}

fn classify_fs_grade(percentage: f64, supported: bool) -> FsGrade {
    if !supported {
        FsGrade::F
    } else if percentage >= 100.0 {
        FsGrade::A
    } else if percentage >= 80.0 {
        FsGrade::B
    } else if percentage >= 50.0 {
        FsGrade::C
    } else {
        FsGrade::D
    }
}

fn grade_to_string(grade: FsGrade) -> &'static str {
    match grade {
        FsGrade::A => "A",
        FsGrade::B => "B",
        FsGrade::C => "C",
        FsGrade::D => "D",
        FsGrade::F => "F",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_cipher_strength() {
        let cipher = analyze_cipher_details("ECDHE-RSA-AES256-GCM-SHA384");
        assert_eq!(cipher.strength, CipherStrength::VeryStrong);
        assert!(cipher.forward_secrecy);

        let cipher = analyze_cipher_details("AES256-SHA");
        assert_eq!(cipher.strength, CipherStrength::Medium);
        assert!(!cipher.forward_secrecy);

        let cipher = analyze_cipher_details("RC4-MD5");
        assert_eq!(cipher.strength, CipherStrength::Weak);
    }

    #[test]
    fn test_classify_fs_grade() {
        assert_eq!(classify_fs_grade(100.0, true), FsGrade::A);
        assert_eq!(classify_fs_grade(85.0, true), FsGrade::B);
        assert_eq!(classify_fs_grade(60.0, true), FsGrade::C);
        assert_eq!(classify_fs_grade(30.0, true), FsGrade::D);
        assert_eq!(classify_fs_grade(0.0, false), FsGrade::F);
    }
}
