// Sweet32 Vulnerability Test
// CVE-2016-2183 (3DES), CVE-2016-6329 (Blowfish)
//
// Sweet32 is a birthday attack against 64-bit block ciphers like 3DES and Blowfish.
// After 2^32 blocks, collisions become likely, allowing attackers to recover plaintext.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;

/// Sweet32 vulnerability tester
pub struct Sweet32Tester {
    target: Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherProbeStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

impl Sweet32Tester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Sweet32 vulnerability
    pub async fn test(&self) -> Result<Sweet32TestResult> {
        let (des3_ciphers, des3_inconclusive) = self.test_3des_ciphers().await?;
        let (blowfish_ciphers, blowfish_inconclusive) = self.test_blowfish_ciphers().await?;

        let vulnerable = !des3_ciphers.is_empty() || !blowfish_ciphers.is_empty();
        let inconclusive = !vulnerable && (des3_inconclusive || blowfish_inconclusive);

        let details = if vulnerable {
            let mut parts = Vec::new();
            if !des3_ciphers.is_empty() {
                parts.push(format!("3DES ciphers supported: {}", des3_ciphers.len()));
            }
            if !blowfish_ciphers.is_empty() {
                parts.push(format!(
                    "Blowfish ciphers supported: {}",
                    blowfish_ciphers.len()
                ));
            }
            let cve = match (des3_ciphers.is_empty(), blowfish_ciphers.is_empty()) {
                (false, false) => "CVE-2016-2183, CVE-2016-6329",
                (false, true) => "CVE-2016-2183",
                (true, false) => "CVE-2016-6329",
                (true, true) => "CVE-2016-2183, CVE-2016-6329",
            };
            format!("Vulnerable to Sweet32 ({}): {}", cve, parts.join(", "))
        } else if inconclusive {
            "SWEET32 test inconclusive - unable to determine 64-bit block cipher support"
                .to_string()
        } else {
            "Not vulnerable - No 64-bit block ciphers (3DES, Blowfish) supported".to_string()
        };

        Ok(Sweet32TestResult {
            vulnerable,
            inconclusive,
            des3_ciphers,
            blowfish_ciphers,
            details,
        })
    }

    /// Test for 3DES cipher support
    async fn test_3des_ciphers(&self) -> Result<(Vec<String>, bool)> {
        let mut supported = Vec::new();
        let mut inconclusive = false;
        let des3_ciphers = vec![
            "DES-CBC3-SHA",
            "DES-CBC3-MD5",
            "EDH-RSA-DES-CBC3-SHA",
            "EDH-DSS-DES-CBC3-SHA",
            "ECDHE-RSA-DES-CBC3-SHA",
            "ECDHE-ECDSA-DES-CBC3-SHA",
            "PSK-3DES-EDE-CBC-SHA",
            "KRB5-DES-CBC3-SHA",
            "KRB5-DES-CBC3-MD5",
        ];

        for cipher in des3_ciphers {
            match self.test_cipher(cipher).await? {
                CipherProbeStatus::Supported => supported.push(cipher.to_string()),
                CipherProbeStatus::NotSupported => {}
                CipherProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((supported, inconclusive))
    }

    /// Test for Blowfish cipher support
    async fn test_blowfish_ciphers(&self) -> Result<(Vec<String>, bool)> {
        let mut supported = Vec::new();
        let mut inconclusive = false;
        let blowfish_ciphers = vec![
            "BF-CBC",
            "BF-CFB",
            "BF-ECB",
            "BF-OFB",
            "BF-SHA",
            "EDH-RSA-BF-CBC-SHA",
            "EDH-DSS-BF-CBC-SHA",
        ];

        for cipher in blowfish_ciphers {
            match self.test_cipher(cipher).await? {
                CipherProbeStatus::Supported => supported.push(cipher.to_string()),
                CipherProbeStatus::NotSupported => {}
                CipherProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((supported, inconclusive))
    }

    /// Test if a specific cipher is supported
    async fn test_cipher(&self, cipher: &str) -> Result<CipherProbeStatus> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, Duration::from_secs(3), None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(CipherProbeStatus::Inconclusive),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Try to set the specific cipher
        match builder.set_cipher_list(cipher) {
            Ok(_) => {
                let connector = builder.build();
                match connector.connect(&self.target.hostname, std_stream) {
                    Ok(_) => Ok(CipherProbeStatus::Supported),
                    Err(_) => Ok(CipherProbeStatus::NotSupported),
                }
            }
            Err(_) => Ok(CipherProbeStatus::NotSupported),
        }
    }
}

/// Sweet32 test result
#[derive(Debug, Clone)]
pub struct Sweet32TestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub des3_ciphers: Vec<String>,
    pub blowfish_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    #[test]
    fn test_sweet32_result_not_vulnerable() {
        let result = Sweet32TestResult {
            vulnerable: false,
            inconclusive: false,
            des3_ciphers: vec![],
            blowfish_ciphers: vec![],
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.des3_ciphers.is_empty());
        assert!(result.blowfish_ciphers.is_empty());
    }

    #[test]
    fn test_sweet32_result_vulnerable() {
        let result = Sweet32TestResult {
            vulnerable: true,
            inconclusive: false,
            des3_ciphers: vec!["DES-CBC3-SHA".to_string()],
            blowfish_ciphers: vec![],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert_eq!(result.des3_ciphers.len(), 1);
    }

    #[tokio::test]
    async fn test_sweet32_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .unwrap();

        let tester = Sweet32Tester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.des3_ciphers.is_empty());
        assert!(result.blowfish_ciphers.is_empty());
        assert!(
            result.details.to_ascii_lowercase().contains("inconclusive"),
            "inactive target must not be reported as a clean SWEET32 pass: {}",
            result.details
        );
    }

    #[test]
    fn test_sweet32_result_details_contains_cipher() {
        let result = Sweet32TestResult {
            vulnerable: true,
            inconclusive: false,
            des3_ciphers: vec!["DES-CBC3-SHA".to_string()],
            blowfish_ciphers: vec![],
            details: "DES-CBC3-SHA supported".to_string(),
        };
        assert!(result.details.contains("DES-CBC3-SHA"));
    }

    #[test]
    fn test_sweet32_result_details_contains_blowfish() {
        let result = Sweet32TestResult {
            vulnerable: true,
            inconclusive: false,
            des3_ciphers: vec![],
            blowfish_ciphers: vec!["BF-CBC-SHA".to_string()],
            details: "Blowfish cipher supported: BF-CBC-SHA".to_string(),
        };
        assert!(result.details.contains("Blowfish"));
    }
}
