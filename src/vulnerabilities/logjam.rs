// LOGJAM Vulnerability Test
// CVE-2015-4000
//
// LOGJAM allows attackers to downgrade TLS connections to use weak 512-bit
// Diffie-Hellman parameters, making it possible to break the encryption through
// precomputation attacks.

use super::cipher_probe::{CipherProbeStatus, probe_cipher_suite};
use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::protocols::Protocol;
use crate::utils::network::Target;
use std::time::Duration;

/// LOGJAM vulnerability tester
pub struct LogjamTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
    sni_hostname: Option<String>,
}

/// Minimum DH parameter size (bits) considered secure. Groups below this are
/// reported as weak per current guidance (NIST SP 800-57 deprecates <2048-bit DH).
const MIN_SECURE_DH_BITS: u32 = 2048;

/// Export-grade DH cipher suites (IANA wire IDs). They are probed by
/// cipher-suite ID over a raw ClientHello because the vendored OpenSSL build is
/// compiled without export ciphers, so `set_cipher_list` cannot offer them — an
/// OpenSSL probe would always report them unsupported regardless of the server
/// (a false negative for LOGJAM).
const EXPORT_DH_CIPHER_SUITES: &[u16] = &[0x0014, 0x0011, 0x0063, 0x0065];

/// Protocol versions under which export DH suites were historically offered.
const EXPORT_DH_PROBE_PROTOCOLS: &[Protocol] = &[Protocol::TLS10, Protocol::SSLv3];

/// Outcome of probing a single cipher for connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogjamProbeStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

/// Outcome of measuring the server's ephemeral DH parameter size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WeakDhStatus {
    /// DH parameters below the secure minimum; carries the measured key size.
    Weak {
        bits: u32,
    },
    Strong,
    Inconclusive,
}

impl WeakDhStatus {
    fn is_weak(self) -> bool {
        matches!(self, Self::Weak { .. })
    }

    fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }
}

impl LogjamTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
            sni_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before each LOGJAM probe.
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

    /// Effective SNI hostname for OpenSSL-based probes: the explicit override if
    /// set, otherwise the target hostname.
    fn effective_sni(&self) -> &str {
        self.sni_hostname
            .as_deref()
            .unwrap_or(self.target.hostname.as_str())
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

    /// Test for LOGJAM vulnerability
    pub async fn test(&self) -> Result<LogjamTestResult> {
        let (export_dh, export_inconclusive) = self.test_export_dh().await?;
        let weak_dh = self.test_weak_dh_params().await?;
        let (dhe_ciphers, dhe_inconclusive) = self.test_dhe_ciphers().await?;

        let weak_dh_bits = match weak_dh {
            WeakDhStatus::Weak { bits } => Some(bits),
            _ => None,
        };
        let weak_dh_params = weak_dh.is_weak();
        let vulnerable = export_dh || weak_dh_params;
        let inconclusive =
            !vulnerable && (export_inconclusive || weak_dh.is_inconclusive() || dhe_inconclusive);

        let details = if vulnerable {
            let mut parts: Vec<String> = Vec::new();
            if export_dh {
                parts.push("Export-grade DH supported".to_string());
            }
            match weak_dh_bits {
                Some(bits) if bits > 0 => parts.push(format!(
                    "Weak DH parameters ({} bits, below {}-bit minimum)",
                    bits, MIN_SECURE_DH_BITS
                )),
                Some(_) => parts.push(
                    "Weak DH parameters (rejected by the TLS library as too small)".to_string(),
                ),
                None => {}
            }
            format!("Vulnerable to LOGJAM (CVE-2015-4000): {}", parts.join(", "))
        } else if inconclusive {
            "LOGJAM test inconclusive - unable to determine DH cipher/parameter support".to_string()
        } else if !dhe_ciphers.is_empty() {
            "Not vulnerable - DHE supported with strong parameters".to_string()
        } else {
            "Not vulnerable - DHE not supported".to_string()
        };

        Ok(LogjamTestResult {
            vulnerable,
            inconclusive,
            export_dh_supported: export_dh,
            weak_dh_params,
            dhe_ciphers,
            details,
        })
    }

    /// Test for export-grade DH cipher support.
    ///
    /// Returns `(supported, inconclusive)`. Export suites are probed by their
    /// wire cipher-suite ID over a raw ClientHello rather than via OpenSSL,
    /// because the vendored OpenSSL build cannot offer export ciphers.
    async fn test_export_dh(&self) -> Result<(bool, bool)> {
        let mut inconclusive = false;
        for &hexcode in EXPORT_DH_CIPHER_SUITES {
            match probe_cipher_suite(
                &self.target,
                hexcode,
                EXPORT_DH_PROBE_PROTOCOLS,
                self.starttls,
                self.sni_hostname.as_deref(),
                self.starttls_hostname.as_deref(),
            )
            .await
            {
                CipherProbeStatus::Supported => return Ok((true, false)),
                CipherProbeStatus::NotSupported => {}
                CipherProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((false, inconclusive))
    }

    /// Test for weak DH parameters
    ///
    /// Performance optimization: Wraps blocking OpenSSL operations in spawn_blocking
    /// to prevent blocking the async runtime.
    async fn test_weak_dh_params(&self) -> Result<WeakDhStatus> {
        use openssl::pkey::Id;
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let hostname = self.effective_sni().to_string();

        let stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return Ok(WeakDhStatus::Inconclusive),
        };

        // Convert to std stream for OpenSSL
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        // Wrap blocking SSL operations in spawn_blocking
        let result = tokio::task::spawn_blocking(move || -> crate::Result<WeakDhStatus> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // Certificate validity is irrelevant to the negotiated DH parameter
            // size; a verifying connector would false-negative (report Strong) on
            // bad-cert hosts by failing the handshake at cert validation.
            builder.set_verify(SslVerifyMode::NONE);

            // A security scanner must be able to *measure* weak DH parameters.
            // OpenSSL's default security level rejects sub-2048-bit DH groups
            // during the handshake, so a weak-DH server would fail to connect and
            // be mis-reported as Strong (the weaker the group, the more likely the
            // rejection — a backwards false negative). Drop the security level so
            // the weak parameters are negotiated and measurable via peer_tmp_key().
            builder.set_security_level(0);

            // Set DHE ciphers only
            builder.set_cipher_list("DHE:EDH:!aNULL:!eNULL")?;

            let connector = builder.build();
            match connector.connect(&hostname, std_stream) {
                Ok(ssl_stream) => match ssl_stream.ssl().peer_tmp_key() {
                    Ok(tmp_key) => {
                        if tmp_key.id() == Id::DH {
                            let bits = tmp_key.bits();
                            Ok(if bits < MIN_SECURE_DH_BITS {
                                WeakDhStatus::Weak { bits }
                            } else {
                                WeakDhStatus::Strong
                            })
                        } else {
                            Ok(WeakDhStatus::Strong)
                        }
                    }
                    Err(_) => Ok(WeakDhStatus::Inconclusive),
                },
                Err(e) => {
                    // OpenSSL enforces a hard minimum DH modulus (e.g. 512-bit
                    // groups) that even security level 0 will not lower, so the
                    // handshake fails with "dh key too small". That refusal is
                    // itself positive evidence of a dangerously weak group —
                    // report it as weak (exact size unknown, hence bits 0).
                    // Any other handshake failure means the DHE measurement did
                    // not complete; do not report it as a clean strong result.
                    if e.to_string().contains("dh key too small") {
                        Ok(WeakDhStatus::Weak { bits: 0 })
                    } else {
                        Ok(WeakDhStatus::Inconclusive)
                    }
                }
            }
        })
        .await
        .map_err(|e| crate::error::TlsError::Other(format!("Spawn blocking failed: {}", e)))??;

        Ok(result)
    }

    /// Test for DHE cipher support
    async fn test_dhe_ciphers(&self) -> Result<(Vec<String>, bool)> {
        let mut supported = Vec::new();
        let mut inconclusive = false;

        let dhe_ciphers = vec![
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-SHA256",
            "DHE-RSA-AES128-SHA256",
            "DHE-RSA-AES256-SHA",
            "DHE-RSA-AES128-SHA",
            "DHE-RSA-CAMELLIA256-SHA",
            "DHE-RSA-CAMELLIA128-SHA",
            "DHE-DSS-AES256-GCM-SHA384",
            "DHE-DSS-AES128-GCM-SHA256",
            "DHE-DSS-AES256-SHA256",
            "DHE-DSS-AES128-SHA256",
            "DHE-DSS-AES256-SHA",
            "DHE-DSS-AES128-SHA",
        ];

        for cipher in dhe_ciphers {
            match self.test_cipher(cipher).await? {
                LogjamProbeStatus::Supported => supported.push(cipher.to_string()),
                LogjamProbeStatus::NotSupported => {}
                LogjamProbeStatus::Inconclusive => inconclusive = true,
            }
        }

        Ok((supported, inconclusive))
    }

    /// Test if a specific cipher is supported
    ///
    /// Performance optimization: Wraps blocking OpenSSL operations in spawn_blocking
    async fn test_cipher(&self, cipher: &str) -> Result<LogjamProbeStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let hostname = self.effective_sni().to_string();
        let cipher = cipher.to_string();

        let stream = match self.starttls_connect(addr, Duration::from_secs(3)).await {
            Ok(s) => s,
            Err(_) => return Ok(LogjamProbeStatus::Inconclusive),
        };

        // Convert to std stream for OpenSSL
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        // Wrap blocking SSL operations in spawn_blocking
        let result = tokio::task::spawn_blocking(move || -> Result<LogjamProbeStatus> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // Certificate validity is irrelevant to export-DHE cipher support;
            // without this a bad-cert host would false-negative.
            builder.set_verify(SslVerifyMode::NONE);
            // Negotiate weak DHE groups too (see test_weak_dh_params): the
            // default security level would otherwise reject them and hide a
            // weak-DH server's DHE support.
            builder.set_security_level(0);

            // Allow SSL 3.0 for export ciphers
            if cipher.starts_with("EXP")
                && builder
                    .set_min_proto_version(Some(SslVersion::SSL3))
                    .is_err()
            {
                return Ok(LogjamProbeStatus::NotSupported);
            }

            // Try to set the specific cipher
            match builder.set_cipher_list(&cipher) {
                Ok(_) => {
                    let connector = builder.build();
                    match connector.connect(&hostname, std_stream) {
                        Ok(_) => Ok(LogjamProbeStatus::Supported),
                        Err(_) => Ok(LogjamProbeStatus::NotSupported),
                    }
                }
                Err(_) => Ok(LogjamProbeStatus::NotSupported),
            }
        })
        .await
        .map_err(|e| crate::error::TlsError::Other(format!("Spawn blocking failed: {}", e)))??;

        Ok(result)
    }
}

/// LOGJAM test result
#[derive(Debug, Clone)]
pub struct LogjamTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub export_dh_supported: bool,
    pub weak_dh_params: bool,
    pub dhe_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
    use tokio::net::TcpListener;

    #[test]
    fn test_logjam_result_not_vulnerable() {
        let result = LogjamTestResult {
            vulnerable: false,
            inconclusive: false,
            export_dh_supported: false,
            weak_dh_params: false,
            dhe_ciphers: vec![],
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(!result.export_dh_supported);
        assert!(!result.weak_dh_params);
    }

    #[test]
    fn test_logjam_result_vulnerable() {
        let result = LogjamTestResult {
            vulnerable: true,
            inconclusive: false,
            export_dh_supported: true,
            weak_dh_params: false,
            dhe_ciphers: vec!["DHE-RSA-AES256-SHA".to_string()],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.export_dh_supported);
    }

    #[test]
    fn test_logjam_result_debug_contains_details() {
        let result = LogjamTestResult {
            vulnerable: false,
            inconclusive: false,
            export_dh_supported: false,
            weak_dh_params: false,
            dhe_ciphers: vec![],
            details: "Not vulnerable - DHE not supported".to_string(),
        };

        let debug = format!("{:?}", result);
        assert!(debug.contains("Not vulnerable"));
    }

    #[test]
    fn test_logjam_result_details_export_grade() {
        let result = LogjamTestResult {
            vulnerable: true,
            inconclusive: false,
            export_dh_supported: true,
            weak_dh_params: false,
            dhe_ciphers: vec![],
            details: "Vulnerable to LOGJAM (CVE-2015-4000): Export-grade DH supported".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.details.contains("Export-grade"));
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
    async fn test_logjam_not_vulnerable_on_dummy_server() {
        let addr = spawn_dummy_server(30).await;
        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = LogjamTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
    }

    #[tokio::test]
    async fn test_logjam_inactive_target_is_inconclusive() {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = LogjamTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(
            result.details.to_ascii_lowercase().contains("inconclusive"),
            "inactive target must not be reported as a clean LOGJAM pass: {}",
            result.details
        );
    }
}
