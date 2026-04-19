use super::analysis::{classify_fs_grade, grade_to_string};
use super::{ForwardSecrecyAnalysis, ForwardSecrecyCipher, ProtocolAdvancedTester};
use crate::Result;
use openssl::ssl::{SslConnector, SslMethod};
use tokio::time::Duration;

const FS_CIPHERS: &[(&str, &str, &str, &str, u16)] = &[
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

const NON_FS_CIPHERS: &[&str] = &[
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "DES-CBC3-SHA",
];

impl ProtocolAdvancedTester {
    pub async fn test_forward_secrecy_detailed(&self) -> Result<ForwardSecrecyAnalysis> {
        let mut supported_fs_ciphers = Vec::new();
        let mut supported_non_fs_ciphers = Vec::new();

        for (cipher, protocol, kex, enc, bits) in FS_CIPHERS {
            if self.test_cipher_support(cipher).await.unwrap_or(false) {
                supported_fs_ciphers.push(ForwardSecrecyCipher {
                    name: (*cipher).to_string(),
                    protocol: (*protocol).to_string(),
                    key_exchange: (*kex).to_string(),
                    encryption: (*enc).to_string(),
                    bits: *bits,
                });
            }
        }

        for cipher in NON_FS_CIPHERS {
            if self.test_cipher_support(cipher).await.unwrap_or(false) {
                supported_non_fs_ciphers.push((*cipher).to_string());
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

    pub(super) async fn check_fs_preference(&self) -> Result<bool> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);

        let stream =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await?;

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;
        let builder = SslConnector::builder(SslMethod::tls())?;
        let connector = builder.build();
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        let cipher = ssl_stream.ssl().current_cipher().ok_or_else(|| {
            crate::error::TlsError::InvalidHandshake {
                details: "No cipher negotiated".into(),
            }
        })?;

        let cipher_name = cipher.name();
        Ok(cipher_name.contains("ECDHE") || cipher_name.contains("DHE"))
    }
}
