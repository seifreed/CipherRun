// Lucky13 Vulnerability Test
// CVE-2013-0169
//
// Lucky13 is a timing attack against CBC mode ciphers in TLS.
// It exploits timing differences in MAC verification to recover plaintext.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;

mod result;

pub use result::Lucky13TestResult;

/// Lucky13 vulnerability tester
pub struct Lucky13Tester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CbcCipherSupportStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

impl Lucky13Tester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before the Lucky13 probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
        server_mode: bool,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self.starttls_server_mode = server_mode;
        self
    }

    pub fn with_test_all_ips(mut self, test_all_ips: bool) -> Self {
        self.test_all_ips = test_all_ips;
        self
    }

    fn probe_addrs(&self) -> Result<Vec<std::net::SocketAddr>> {
        crate::utils::target_addrs::socket_addrs_for_probe(&self.target, self.test_all_ips)
    }

    /// Connect, upgrading via STARTTLS first for plaintext-first services.
    async fn starttls_connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<tokio::net::TcpStream> {
        crate::utils::network::connect_with_starttls_target(
            addr,
            timeout,
            self.starttls,
            &self.target,
            self.starttls_hostname.as_deref(),
            self.starttls_server_mode,
        )
        .await
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

        Ok(Lucky13TestResult::from_cbc_status(cbc_status))
    }

    /// Test if CBC ciphers are supported.
    async fn test_cbc_ciphers(&self) -> Result<CbcCipherSupportStatus> {
        let mut inconclusive = false;
        for addr in self.probe_addrs()? {
            match self.test_cbc_ciphers_addr(addr).await? {
                CbcCipherSupportStatus::Supported => return Ok(CbcCipherSupportStatus::Supported),
                CbcCipherSupportStatus::NotSupported => {}
                CbcCipherSupportStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok(if inconclusive {
            CbcCipherSupportStatus::Inconclusive
        } else {
            CbcCipherSupportStatus::NotSupported
        })
    }

    async fn test_cbc_ciphers_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<CbcCipherSupportStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

        // Test with various CBC ciphers
        let cbc_ciphers = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA";

        match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(stream) => {
                let std_stream =
                    crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

                let (hostname, use_sni) =
                    crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
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
                    match connector
                        .configure()?
                        .use_server_name_indication(use_sni)
                        .connect(&hostname, std_stream)
                    {
                        Ok(_) => Ok(CbcCipherSupportStatus::Supported),
                        Err(error) => Ok(classify_cbc_handshake_error(&error.to_string())),
                    }
                })
                .await
                .map_err(|e| crate::TlsError::Other(format!("Spawn blocking failed: {e}")))?
            }
            _ => Ok(CbcCipherSupportStatus::Inconclusive),
        }
    }
}

fn classify_cbc_handshake_error(error: &str) -> CbcCipherSupportStatus {
    if crate::utils::network::is_transport_anomaly_error(error) {
        CbcCipherSupportStatus::Inconclusive
    } else {
        CbcCipherSupportStatus::NotSupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::test_support::localhost_target;

    #[test]
    fn test_cbc_handshake_error_without_shared_cipher_is_not_supported() {
        assert_eq!(
            classify_cbc_handshake_error("ssl handshake failure: no shared cipher"),
            CbcCipherSupportStatus::NotSupported
        );
    }

    #[test]
    fn test_cbc_handshake_transport_error_is_inconclusive() {
        assert_eq!(
            classify_cbc_handshake_error("connection reset by peer"),
            CbcCipherSupportStatus::Inconclusive
        );
    }

    #[tokio::test]
    async fn test_lucky13_inactive_target_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = localhost_target(port);

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

        let target = localhost_target(port);

        let tester = Lucky13Tester::new(target);
        let result = tester.test().await.unwrap();

        assert!(!result.cbc_supported);
        assert!(result.inconclusive, "{result:?}");
    }
}
