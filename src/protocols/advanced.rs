// Advanced protocol tests façade.

#[path = "advanced/analysis.rs"]
mod analysis;
#[path = "advanced/cipher_enumeration.rs"]
mod cipher_enumeration;
#[path = "advanced/forward_secrecy.rs"]
mod forward_secrecy;

use crate::Result;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rc4BiasesAnalysis {
    pub rc4_supported: bool,
    pub rc4_ciphers: Vec<String>,
    pub vulnerable_to_appelbaum: bool,
    pub vulnerable_to_bar_mitzvah: bool,
    pub bias_details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsTruncationAnalysis {
    pub vulnerable: bool,
    pub accepts_truncated_hmac: bool,
    pub accepts_no_close_notify: bool,
    pub tested: bool,
    pub details: String,
}

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
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

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
    A,
    B,
    C,
    D,
    F,
}

pub struct ProtocolAdvancedTester {
    pub(super) target: Target,
}

impl ProtocolAdvancedTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

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

        Ok(analysis::build_rc4_report(supported_rc4_ciphers))
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
    fn test_classify_cipher_strength() {
        let cipher = analysis::analyze_cipher_details("ECDHE-RSA-AES256-GCM-SHA384");
        assert_eq!(cipher.strength, CipherStrength::VeryStrong);
        assert!(cipher.forward_secrecy);

        let cipher = analysis::analyze_cipher_details("AES256-SHA");
        assert_eq!(cipher.strength, CipherStrength::Medium);
        assert!(!cipher.forward_secrecy);

        let cipher = analysis::analyze_cipher_details("RC4-MD5");
        assert_eq!(cipher.strength, CipherStrength::Weak);
    }

    #[test]
    fn test_classify_fs_grade() {
        assert_eq!(analysis::classify_fs_grade(100.0, true), FsGrade::A);
        assert_eq!(analysis::classify_fs_grade(85.0, true), FsGrade::B);
        assert_eq!(analysis::classify_fs_grade(60.0, true), FsGrade::C);
        assert_eq!(analysis::classify_fs_grade(30.0, true), FsGrade::D);
        assert_eq!(analysis::classify_fs_grade(0.0, false), FsGrade::F);
    }

    #[test]
    fn test_analyze_cipher_details_aead() {
        let cipher = analysis::analyze_cipher_details("ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(cipher.key_exchange, "ECDHE");
        assert_eq!(cipher.encryption, "AES-128-GCM");
        assert_eq!(cipher.mac, "AEAD");
        assert!(cipher.forward_secrecy);
        assert_eq!(cipher.strength, CipherStrength::VeryStrong);
    }

    #[test]
    fn test_analyze_cipher_details_rsa_cbc() {
        let cipher = analysis::analyze_cipher_details("RSA-AES256-SHA");
        assert_eq!(cipher.key_exchange, "RSA");
        assert_eq!(cipher.encryption, "AES-256-CBC");
        assert_eq!(cipher.mac, "SHA1");
        assert!(!cipher.forward_secrecy);
        assert_eq!(cipher.strength, CipherStrength::Medium);
    }

    #[test]
    fn test_analyze_cipher_details_unknown() {
        let cipher = analysis::analyze_cipher_details("UNKNOWN-CIPHER");
        assert_eq!(cipher.key_exchange, "Unknown");
        assert_eq!(cipher.encryption, "Unknown");
        assert_eq!(cipher.mac, "Unknown");
        assert!(!cipher.forward_secrecy);
    }

    #[test]
    fn test_grade_to_string() {
        assert_eq!(analysis::grade_to_string(FsGrade::A), "A");
        assert_eq!(analysis::grade_to_string(FsGrade::B), "B");
        assert_eq!(analysis::grade_to_string(FsGrade::C), "C");
        assert_eq!(analysis::grade_to_string(FsGrade::D), "D");
        assert_eq!(analysis::grade_to_string(FsGrade::F), "F");
    }

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    async fn spawn_tls_server(max_accepts: usize) -> (SocketAddr, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");

        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let tmp = std::env::temp_dir();
        let cert_path = tmp.join(format!(
            "cipherrun_test_cert_adv_{}_{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");

        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let _ = acceptor.accept(stream).await;
                }
                remaining -= 1;
            }
        });

        (addr, cert_path)
    }

    #[tokio::test]
    async fn test_tls_truncation_default_not_vulnerable() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target");

        let tester = ProtocolAdvancedTester::new(target);
        let result = tester.test_tls_truncation().await.expect("truncation");

        assert!(!result.vulnerable);
        assert!(!result.accepts_truncated_hmac);
        assert!(!result.accepts_no_close_notify);
        assert!(result.details.contains("TLS truncation"));
    }

    #[tokio::test]
    async fn test_cipher_support_and_fs_preference_local_tls() {
        install_crypto_provider();
        let (addr, cert_path) = spawn_tls_server(10).await;

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target");
        let tester = ProtocolAdvancedTester::new(target);

        let supported = tester.test_cipher_support("DEFAULT").await.unwrap_or(false);
        assert!(!supported);

        let preferred = tester.check_fs_preference().await.unwrap_or(false);
        assert!(!preferred);

        let _ = std::fs::remove_file(cert_path);
    }

    #[tokio::test]
    async fn test_rc4_and_forward_secrecy_reports_local_tls() {
        install_crypto_provider();
        let (addr, cert_path) = spawn_tls_server(30).await;

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .expect("target");
        let tester = ProtocolAdvancedTester::new(target);

        let rc4 = tester.test_rc4_biases().await.expect("rc4");
        assert!(!rc4.rc4_supported);
        assert!(rc4.bias_details.contains("RC4"));

        let fs = tester.test_forward_secrecy_detailed().await.expect("fs");
        assert!(!fs.supported);
        assert_eq!(fs.grade, FsGrade::F);
        assert!(fs.details.contains("Forward Secrecy"));

        let _ = std::fs::remove_file(cert_path);
    }
}
