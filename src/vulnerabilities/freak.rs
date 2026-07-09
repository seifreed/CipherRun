// FREAK (Factoring RSA Export Keys) Vulnerability Test
// CVE-2015-0204
//
// FREAK allows attackers to force the use of weak 512-bit RSA export keys
// by manipulating the TLS handshake, making it possible to factor the key
// and decrypt the connection.

use super::cipher_probe::{CipherProbeStatus, probe_cipher_suite};
use crate::Result;
use crate::protocols::Protocol;
use crate::utils::network::Target;

/// FREAK vulnerability tester
pub struct FreakTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
    sni_hostname: Option<String>,
}

/// RSA_EXPORT cipher suites (legacy wire IDs) paired with display names. Probed
/// by cipher-suite ID over a raw ClientHello because the vendored OpenSSL build
/// is compiled without export ciphers, so `set_cipher_list` cannot offer them —
/// an OpenSSL probe would always report them unsupported regardless of the
/// server (a false negative for FREAK).
const EXPORT_RSA_CIPHER_SUITES: &[(u16, &str)] = &[
    (0x0003, "EXP-RC4-MD5"),
    (0x0006, "EXP-RC2-CBC-MD5"),
    (0x0008, "EXP-DES-CBC-SHA"),
    (0x0062, "EXP1024-DES-CBC-SHA"),
    (0x0064, "EXP1024-RC4-SHA"),
    (0x0060, "EXP1024-RC4-MD5"),
    (0x0061, "EXP1024-RC2-CBC-MD5"),
];

/// Protocol versions probed for export-RSA support. A FREAK-vulnerable server
/// accepts an RSA_EXPORT key exchange even under a modern protocol, so TLS 1.2
/// is the primary signal with TLS 1.0 as a fallback.
const FREAK_PROBE_PROTOCOLS: &[Protocol] = &[Protocol::TLS12, Protocol::TLS10];

impl FreakTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
            sni_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before each export-RSA cipher probe.
    /// `hostname` is the STARTTLS negotiation hostname (e.g. XMPP `to=`).
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
    }

    /// Configure an explicit SNI hostname (e.g. `--sni-name`) for each probe.
    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    /// Test for FREAK vulnerability
    pub async fn test(&self) -> Result<FreakTestResult> {
        let (export_ciphers, export_inconclusive) = self.test_export_ciphers().await?;
        let vulnerable = !export_ciphers.is_empty();
        let inconclusive = !vulnerable && export_inconclusive;

        let details = if vulnerable {
            format!(
                "Vulnerable to FREAK (CVE-2015-0204) - Server supports {} RSA export cipher(s): {}",
                export_ciphers.len(),
                export_ciphers.join(", ")
            )
        } else if inconclusive {
            "FREAK test inconclusive - unable to determine RSA export cipher support".to_string()
        } else {
            "Not vulnerable - No RSA export ciphers supported".to_string()
        };

        Ok(FreakTestResult {
            vulnerable,
            inconclusive,
            export_ciphers,
            details,
        })
    }

    /// Test for RSA export cipher support.
    ///
    /// Returns `(supported_names, inconclusive)`. Each suite is probed by its
    /// wire cipher-suite ID; a ServerHello means the server accepted an
    /// export-RSA key exchange (FREAK).
    async fn test_export_ciphers(&self) -> Result<(Vec<String>, bool)> {
        let mut supported = Vec::new();
        let mut inconclusive = false;

        for (hexcode, name) in EXPORT_RSA_CIPHER_SUITES {
            match probe_cipher_suite(
                &self.target,
                *hexcode,
                FREAK_PROBE_PROTOCOLS,
                self.starttls,
                self.sni_hostname.as_deref(),
                self.starttls_hostname.as_deref(),
                false,
            )
            .await
            {
                CipherProbeStatus::Supported => supported.push((*name).to_string()),
                CipherProbeStatus::NotSupported => {}
                CipherProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((supported, inconclusive))
    }
}

/// FREAK test result
#[derive(Debug, Clone)]
pub struct FreakTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub export_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
    use tokio::net::TcpListener;

    #[test]
    fn test_freak_result_not_vulnerable() {
        let result = FreakTestResult {
            vulnerable: false,
            inconclusive: false,
            export_ciphers: vec![],
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.export_ciphers.is_empty());
    }

    #[test]
    fn test_freak_result_vulnerable() {
        let result = FreakTestResult {
            vulnerable: true,
            inconclusive: false,
            export_ciphers: vec!["EXP-RC4-MD5".to_string()],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert_eq!(result.export_ciphers.len(), 1);
    }

    #[test]
    fn test_freak_result_details_mentions_cipher_count() {
        let result = FreakTestResult {
            vulnerable: true,
            inconclusive: false,
            export_ciphers: vec!["EXP-RC4-MD5".to_string(), "EXP-RC2-CBC-MD5".to_string()],
            details: "Vulnerable to FREAK (CVE-2015-0204) - Server supports 2 RSA export cipher(s): EXP-RC4-MD5, EXP-RC2-CBC-MD5".to_string(),
        };
        assert!(result.details.contains("2 RSA export cipher"));
    }

    /// A server that reads each ClientHello and replies with a fatal
    /// `handshake_failure` TLS alert, i.e. it conclusively rejects every offered
    /// cipher — the behaviour of a real TLS server that does not support the
    /// probed export suite.
    async fn spawn_rejecting_server(max_accepts: usize) -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // record: Alert (0x15), TLS 1.2 (0x0303), len 2, fatal (0x02),
        // handshake_failure (0x28).
        const HANDSHAKE_FAILURE_ALERT: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket.write_all(&HANDSHAKE_FAILURE_ALERT).await;
                    remaining -= 1;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_freak_tester_no_export_support() {
        // 7 export suites probed across 2 protocols => up to 14 connections.
        let addr = spawn_rejecting_server(EXPORT_RSA_CIPHER_SUITES.len() * 2).await;
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = FreakTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
        assert!(result.export_ciphers.is_empty());
    }

    #[tokio::test]
    async fn test_freak_inactive_target_is_inconclusive() {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = FreakTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.export_ciphers.is_empty());
        assert!(
            result.details.to_ascii_lowercase().contains("inconclusive"),
            "inactive target must not be reported as a clean FREAK pass: {}",
            result.details
        );
    }

    #[test]
    fn test_freak_result_details() {
        let result = FreakTestResult {
            vulnerable: false,
            inconclusive: false,
            export_ciphers: Vec::new(),
            details: "No export ciphers".to_string(),
        };
        assert!(result.details.contains("No export"));
    }

    #[test]
    fn test_freak_result_not_vulnerable_details_text() {
        let result = FreakTestResult {
            vulnerable: false,
            inconclusive: false,
            export_ciphers: Vec::new(),
            details: "Not vulnerable - No RSA export ciphers supported".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }
}
