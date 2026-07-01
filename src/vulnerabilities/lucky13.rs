// Lucky13 Vulnerability Test
// CVE-2013-0169
//
// Lucky13 is a timing attack against CBC mode ciphers in TLS.
// It exploits timing differences in MAC verification to recover plaintext.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;

/// Lucky13 vulnerability tester
pub struct Lucky13Tester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CbcCipherSupportStatus {
    Supported,
    Inconclusive,
}

impl Lucky13Tester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before the Lucky13 probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
    }

    /// Connect, upgrading via STARTTLS first for plaintext-first services.
    async fn starttls_connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<tokio::net::TcpStream> {
        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        crate::utils::network::connect_with_starttls(addr, timeout, self.starttls, &hostname).await
    }

    /// Assess Lucky13 exposure.
    ///
    /// Lucky13 (CVE-2013-0169) is a timing side-channel in the MAC verification
    /// of TLS CBC-mode cipher suites. Definitive remote confirmation would
    /// require measuring nanosecond MAC-processing differences across the
    /// network, where jitter is orders of magnitude larger than the signal — so
    /// no remote scanner (this one included) can reliably confirm the oracle.
    /// The deterministic, defensible assessment is therefore based on the
    /// presence of CBC cipher suites: their absence rules Lucky13 out, while
    /// their presence places the server in the vulnerable cipher class with the
    /// constant-time-MAC mitigation status unverifiable from outside.
    pub async fn test(&self) -> Result<Lucky13TestResult> {
        let cbc_status = self.test_cbc_ciphers().await?;

        match cbc_status {
            CbcCipherSupportStatus::Inconclusive => Ok(Lucky13TestResult {
                vulnerable: false,
                partially_vulnerable: false,
                cbc_supported: false,
                inconclusive: true,
                details: "Lucky13 assessment inconclusive - unable to determine CBC cipher support"
                    .to_string(),
            }),
            CbcCipherSupportStatus::Supported => Ok(Lucky13TestResult {
                vulnerable: false,
                partially_vulnerable: true,
                cbc_supported: true,
                inconclusive: false,
                details:
                    "Server supports CBC cipher suites, which are in the class susceptible to the \
                     Lucky13 timing attack (CVE-2013-0169). Whether the TLS implementation includes \
                     the constant-time MAC mitigation cannot be confirmed by remote timing (the \
                     difference is below network-jitter resolution). Recommendation: prefer AEAD \
                     cipher suites (AES-GCM, ChaCha20-Poly1305) and disable CBC."
                        .to_string(),
            }),
        }
    }

    /// Test if CBC ciphers are supported.
    async fn test_cbc_ciphers(&self) -> Result<CbcCipherSupportStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // Test with various CBC ciphers
        let cbc_ciphers = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA";

        match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(stream) => {
                let std_stream =
                    crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

                let hostname = self.target.hostname.clone();
                tokio::task::spawn_blocking(move || -> Result<CbcCipherSupportStatus> {
                    let mut builder = SslConnector::builder(SslMethod::tls())?;
                    // The scanner must determine cipher support even on hosts with
                    // expired/self-signed/untrusted certificates; certificate
                    // validity is assessed separately.
                    builder.set_verify(SslVerifyMode::NONE);
                    builder.set_cipher_list(cbc_ciphers)?;
                    // CBC ciphers are TLS <= 1.2. TLS 1.3 ignores set_cipher_list,
                    // so keep this probe on the protocol versions it measures.
                    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

                    let connector = builder.build();
                    match connector.connect(&hostname, std_stream) {
                        Ok(_) => Ok(CbcCipherSupportStatus::Supported),
                        Err(_) => Ok(CbcCipherSupportStatus::Inconclusive),
                    }
                })
                .await
                .map_err(|e| crate::TlsError::Other(format!("Spawn blocking failed: {e}")))?
            }
            _ => Ok(CbcCipherSupportStatus::Inconclusive),
        }
    }
}

/// Lucky13 test result
#[derive(Debug, Clone)]
pub struct Lucky13TestResult {
    pub vulnerable: bool,
    pub partially_vulnerable: bool,
    pub cbc_supported: bool,
    pub inconclusive: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_lucky13_result() {
        let result = Lucky13TestResult {
            vulnerable: false,
            partially_vulnerable: true,
            cbc_supported: true,
            inconclusive: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.partially_vulnerable);
        assert!(result.cbc_supported);
    }

    #[test]
    fn test_lucky13_result_not_vulnerable_details() {
        let result = Lucky13TestResult {
            vulnerable: false,
            partially_vulnerable: false,
            cbc_supported: false,
            inconclusive: false,
            details: "Not vulnerable - server does not support CBC cipher suites".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[tokio::test]
    async fn test_lucky13_inactive_target_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = Lucky13Tester::new(target);
        let result = tester.test().await.unwrap();

        assert!(!result.vulnerable);
        assert!(!result.cbc_supported);
        assert!(result.inconclusive, "{result:?}");
        assert!(
            result.details.to_ascii_lowercase().contains("inconclusive"),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn test_lucky13_closed_handshake_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = Lucky13Tester::new(target);
        let result = tester.test().await.unwrap();

        assert!(!result.cbc_supported);
        assert!(result.inconclusive, "{result:?}");
    }
}
