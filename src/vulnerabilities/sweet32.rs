// Sweet32 Vulnerability Test
// CVE-2016-2183 (3DES in TLS)
//
// Sweet32 is a birthday attack against 64-bit block ciphers. After ~2^32 blocks
// under one key, collisions become likely, allowing plaintext recovery. In TLS
// the affected primitive is 3DES (DES-EDE-CBC). Blowfish is not standardized as
// a TLS cipher suite — the Blowfish Sweet32 variant (CVE-2016-6329) targets
// protocols like OpenVPN, not TLS — so it is not probed here.

use super::cipher_probe::{CipherProbeStatus, probe_cipher_suite};
use crate::Result;
use crate::protocols::Protocol;
use crate::utils::network::Target;

/// Sweet32 vulnerability tester
pub struct Sweet32Tester {
    target: Target,
}

/// 3DES (64-bit block) cipher suites (IANA wire IDs) paired with display names.
/// Probed by cipher-suite ID over a raw ClientHello because the vendored OpenSSL
/// build is compiled without 3DES, so `set_cipher_list` cannot offer these names
/// — an OpenSSL probe would always report them unsupported regardless of the
/// server (a false negative for Sweet32).
const SWEET32_3DES_CIPHER_SUITES: &[(u16, &str)] = &[
    (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
    (0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"),
    (0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"),
    (0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"),
    (0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"),
    (0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"),
];

/// Protocol versions probed for 3DES support. 3DES suites are offered from
/// SSL 3.0 through TLS 1.2 (TLS 1.3 dropped them entirely).
const SWEET32_PROBE_PROTOCOLS: &[Protocol] = &[Protocol::TLS12, Protocol::TLS10];

impl Sweet32Tester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Sweet32 vulnerability
    pub async fn test(&self) -> Result<Sweet32TestResult> {
        let (des3_ciphers, des3_inconclusive) = self.test_3des_ciphers().await?;

        let vulnerable = !des3_ciphers.is_empty();
        let inconclusive = !vulnerable && des3_inconclusive;

        let details = if vulnerable {
            format!(
                "Vulnerable to Sweet32 (CVE-2016-2183): {} 3DES cipher(s) supported: {}",
                des3_ciphers.len(),
                des3_ciphers.join(", ")
            )
        } else if inconclusive {
            "SWEET32 test inconclusive - unable to determine 3DES cipher support".to_string()
        } else {
            "Not vulnerable - No 3DES (64-bit block) ciphers supported".to_string()
        };

        Ok(Sweet32TestResult {
            vulnerable,
            inconclusive,
            des3_ciphers,
            details,
        })
    }

    /// Test for 3DES cipher support.
    ///
    /// Returns `(supported_names, inconclusive)`. Each suite is probed by its
    /// wire cipher-suite ID; a ServerHello means the server offers 3DES.
    async fn test_3des_ciphers(&self) -> Result<(Vec<String>, bool)> {
        let mut supported = Vec::new();
        let mut inconclusive = false;

        for (hexcode, name) in SWEET32_3DES_CIPHER_SUITES {
            match probe_cipher_suite(&self.target, *hexcode, SWEET32_PROBE_PROTOCOLS).await {
                CipherProbeStatus::Supported => supported.push((*name).to_string()),
                CipherProbeStatus::NotSupported => {}
                CipherProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((supported, inconclusive))
    }
}

/// Sweet32 test result
#[derive(Debug, Clone)]
pub struct Sweet32TestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub des3_ciphers: Vec<String>,
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
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.des3_ciphers.is_empty());
    }

    #[test]
    fn test_sweet32_result_vulnerable() {
        let result = Sweet32TestResult {
            vulnerable: true,
            inconclusive: false,
            des3_ciphers: vec!["TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string()],
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
            des3_ciphers: vec!["TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string()],
            details: "TLS_RSA_WITH_3DES_EDE_CBC_SHA supported".to_string(),
        };
        assert!(result.details.contains("3DES_EDE"));
    }
}
