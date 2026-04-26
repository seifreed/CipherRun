// RC4 Cipher Testing
// RC4 is considered insecure due to statistical biases (Appelbaum attack, etc.)
// RFC 7465 prohibits RC4 in TLS

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;

/// RC4 cipher tester
pub struct Rc4Tester {
    target: Target,
}

impl Rc4Tester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for RC4 cipher support
    pub async fn test(&self) -> Result<Rc4TestResult> {
        let (rc4_ciphers, inconclusive) = self.test_rc4_ciphers().await?;
        let vulnerable = !rc4_ciphers.is_empty();

        let details = if vulnerable {
            format!(
                "INSECURE: {} RC4 cipher(s) supported (RFC 7465 prohibits RC4): {}",
                rc4_ciphers.len(),
                rc4_ciphers.join(", ")
            )
        } else if inconclusive {
            "RC4 test inconclusive - unable to determine RC4 cipher support".to_string()
        } else {
            "Good: No RC4 ciphers supported".to_string()
        };

        Ok(Rc4TestResult {
            vulnerable,
            inconclusive: inconclusive && !vulnerable,
            rc4_ciphers,
            details,
        })
    }

    /// Test for RC4 cipher support
    async fn test_rc4_ciphers(&self) -> Result<(Vec<String>, bool)> {
        let mut supported = Vec::new();
        let mut inconclusive = false;

        // List of RC4 ciphers to test
        let rc4_ciphers = vec![
            // RC4-MD5
            "RC4-MD5",
            "RC4-SHA",
            "EXP-RC4-MD5",
            "EXP1024-RC4-MD5",
            "EXP1024-RC4-SHA",
            // ECDHE with RC4
            "ECDHE-RSA-RC4-SHA",
            "ECDHE-ECDSA-RC4-SHA",
            // ECDH with RC4
            "ECDH-RSA-RC4-SHA",
            "ECDH-ECDSA-RC4-SHA",
            // PSK with RC4
            "PSK-RC4-SHA",
            "ECDHE-PSK-RC4-SHA",
            // Anonymous RC4
            "ADH-RC4-MD5",
            "AECDH-RC4-SHA",
        ];

        for cipher in rc4_ciphers {
            match self.test_cipher(cipher).await? {
                Rc4ProbeStatus::Supported => supported.push(cipher.to_string()),
                Rc4ProbeStatus::NotSupported => {}
                Rc4ProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((supported, inconclusive))
    }

    /// Test if a specific RC4 cipher is supported
    async fn test_cipher(&self, cipher: &str) -> Result<Rc4ProbeStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match crate::utils::network::connect_with_timeout(addr, Duration::from_secs(3), None).await
        {
            Ok(stream) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;

                // Allow older protocols that might support RC4
                if cipher.starts_with("EXP") {
                    builder.set_min_proto_version(Some(SslVersion::SSL3))?;
                } else {
                    builder.set_min_proto_version(Some(SslVersion::TLS1))?;
                }

                // Try to set the specific RC4 cipher
                match builder.set_cipher_list(cipher) {
                    Ok(_) => {
                        let connector = builder.build();
                        match connector.connect(&self.target.hostname, std_stream) {
                            Ok(_) => Ok(Rc4ProbeStatus::Supported),
                            Err(_) => Ok(Rc4ProbeStatus::NotSupported),
                        }
                    }
                    Err(_) => Ok(Rc4ProbeStatus::NotSupported),
                }
            }
            _ => Ok(Rc4ProbeStatus::Inconclusive),
        }
    }

    /// Test if RC4 is preferred (worst case scenario)
    pub async fn test_rc4_preferred(&self) -> Result<bool> {
        Ok(self.test_rc4_preferred_status().await? == Rc4PreferenceStatus::Preferred)
    }

    /// Test if RC4 is preferred (worst case scenario), preserving inconclusive outcomes.
    pub async fn test_rc4_preferred_status(&self) -> Result<Rc4PreferenceStatus> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match crate::utils::network::connect_with_timeout(addr, Duration::from_secs(5), None).await
        {
            Ok(stream) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;

                // Set cipher list with RC4 first, then strong ciphers
                match builder.set_cipher_list("RC4-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256") {
                    Ok(_) => {
                        let connector = builder.build();
                        match connector.connect(&self.target.hostname, std_stream) {
                            Ok(ssl_stream) => {
                                // Check which cipher was selected
                                if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                                    let cipher_name = cipher.name();
                                    if cipher_name.contains("RC4") {
                                        Ok(Rc4PreferenceStatus::Preferred)
                                    } else {
                                        Ok(Rc4PreferenceStatus::NotPreferred)
                                    }
                                } else {
                                    Ok(Rc4PreferenceStatus::Inconclusive)
                                }
                            }
                            Err(_) => Ok(Rc4PreferenceStatus::NotPreferred),
                        }
                    }
                    Err(_) => Ok(Rc4PreferenceStatus::Inconclusive),
                }
            }
            _ => Ok(Rc4PreferenceStatus::Inconclusive),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rc4ProbeStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rc4PreferenceStatus {
    Preferred,
    NotPreferred,
    Inconclusive,
}

/// RC4 test result
#[derive(Debug, Clone)]
pub struct Rc4TestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub rc4_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use tokio::net::TcpListener;

    #[test]
    fn test_rc4_result_not_vulnerable() {
        let result = Rc4TestResult {
            vulnerable: false,
            inconclusive: false,
            rc4_ciphers: vec![],
            details: "Good".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.rc4_ciphers.is_empty());
    }

    #[test]
    fn test_rc4_result_vulnerable() {
        let result = Rc4TestResult {
            vulnerable: true,
            inconclusive: false,
            rc4_ciphers: vec!["RC4-SHA".to_string(), "RC4-MD5".to_string()],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert_eq!(result.rc4_ciphers.len(), 2);
    }

    #[test]
    fn test_rc4_result_details_contains_text() {
        let result = Rc4TestResult {
            vulnerable: false,
            inconclusive: false,
            rc4_ciphers: vec![],
            details: "No RC4 ciphers supported".to_string(),
        };
        assert!(result.details.contains("RC4"));
    }

    async fn spawn_dummy_server(max_accepts: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((socket, _)) = listener.accept().await {
                    drop(socket);
                }
                remaining -= 1;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_rc4_tester_no_support() {
        let addr = spawn_dummy_server(30).await;
        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = Rc4Tester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
    }

    #[tokio::test]
    async fn test_rc4_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = Rc4Tester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "closed TCP target must not be reported as no RC4 support: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_rc4_preferred_inactive_target_status_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = Rc4Tester::new(target);
        let status = tester.test_rc4_preferred_status().await.unwrap();
        assert_eq!(status, Rc4PreferenceStatus::Inconclusive);
    }

    #[test]
    fn test_rc4_result_details_contains_cipher_name() {
        let result = Rc4TestResult {
            vulnerable: true,
            inconclusive: false,
            rc4_ciphers: vec!["RC4-SHA".to_string()],
            details: "INSECURE: 1 RC4 cipher(s) supported (RFC 7465 prohibits RC4): RC4-SHA"
                .to_string(),
        };
        assert!(result.details.contains("RC4"));
        assert!(result.details.contains("RC4-SHA"));
    }

    #[test]
    fn test_rc4_result_details_non_vulnerable() {
        let result = Rc4TestResult {
            vulnerable: false,
            inconclusive: false,
            rc4_ciphers: Vec::new(),
            details: "Good: No RC4 ciphers supported".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("No RC4"));
    }

    #[test]
    fn test_rc4_result_details_mentions_rfc() {
        let result = Rc4TestResult {
            vulnerable: true,
            inconclusive: false,
            rc4_ciphers: vec!["RC4-SHA".to_string()],
            details: "INSECURE: 1 RC4 cipher(s) supported (RFC 7465 prohibits RC4): RC4-SHA"
                .to_string(),
        };
        assert!(result.details.contains("RFC 7465"));
    }
}
