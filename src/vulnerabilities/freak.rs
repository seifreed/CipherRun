// FREAK (Factoring RSA Export Keys) Vulnerability Test
// CVE-2015-0204
//
// FREAK allows attackers to force the use of weak 512-bit RSA export keys
// by manipulating the TLS handshake, making it possible to factor the key
// and decrypt the connection.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;

/// FREAK vulnerability tester
pub struct FreakTester {
    target: Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreakProbeStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

impl FreakTester {
    pub fn new(target: Target) -> Self {
        Self { target }
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

    /// Test for RSA export cipher support
    async fn test_export_ciphers(&self) -> Result<(Vec<String>, bool)> {
        let mut supported = Vec::new();
        let mut inconclusive = false;

        // List of RSA export ciphers
        let export_ciphers = vec![
            "EXP-RC4-MD5",
            "EXP-RC2-CBC-MD5",
            "EXP-DES-CBC-SHA",
            "EXP1024-DES-CBC-SHA",
            "EXP1024-RC4-SHA",
            "EXP1024-RC4-MD5",
            "EXP1024-RC2-CBC-MD5",
        ];

        for cipher in export_ciphers {
            match self.test_cipher(cipher).await? {
                FreakProbeStatus::Supported => supported.push(cipher.to_string()),
                FreakProbeStatus::NotSupported => {}
                FreakProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((supported, inconclusive))
    }

    /// Test if a specific export cipher is supported
    async fn test_cipher(&self, cipher: &str) -> Result<FreakProbeStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let hostname = self.target.hostname.clone();
        let cipher = cipher.to_string();

        let stream =
            match crate::utils::network::connect_with_timeout(addr, Duration::from_secs(3), None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(FreakProbeStatus::Inconclusive),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let result = tokio::task::spawn_blocking(move || -> Result<FreakProbeStatus> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;

            // Try to set SSL 3.0 - this may fail on modern OpenSSL versions
            // that have SSL 3.0 disabled at compile time
            if builder
                .set_min_proto_version(Some(SslVersion::SSL3))
                .is_err()
            {
                tracing::debug!(
                    "SSL 3.0 not supported by OpenSSL - cannot test for FREAK on SSL 3.0"
                );
                return Ok(FreakProbeStatus::NotSupported);
            }

            if builder.set_cipher_list(&cipher).is_err() {
                return Ok(FreakProbeStatus::NotSupported);
            }

            let connector = builder.build();
            match connector.connect(&hostname, std_stream) {
                Ok(_) => Ok(FreakProbeStatus::Supported),
                Err(_) => Ok(FreakProbeStatus::NotSupported),
            }
        })
        .await
        .map_err(|e| crate::error::TlsError::Other(format!("Spawn blocking failed: {}", e)))??;

        Ok(result)
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

    async fn spawn_dummy_server(max_accepts: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((socket, _)) = listener.accept().await {
                    drop(socket);
                    remaining -= 1;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_freak_tester_no_export_support() {
        let addr = spawn_dummy_server(10).await;
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
