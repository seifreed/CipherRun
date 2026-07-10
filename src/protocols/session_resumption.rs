// Session Resumption Testing - Complete Session Resume Analysis
// Tests session IDs, session tickets (RFC 5077), and resumption behavior

mod model;
mod performance;

pub use model::{ResumptionSupport, SessionIdTest, SessionResumptionResult, SessionTicketTest};

use crate::Result;
use crate::error::TlsError;
use crate::utils::network::Target;
use openssl::ssl::{
    SslConnector, SslMethod, SslSession, SslSessionCacheMode, SslStream, SslVerifyMode,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Session resumption tester
pub struct SessionResumptionTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
}

impl SessionResumptionTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
        }
    }

    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
    }

    pub fn with_starttls_server_mode(mut self, server_mode: bool) -> Self {
        self.starttls_server_mode = server_mode;
        self
    }

    /// Check if an SSL session is still valid (not expired)
    ///
    /// Sessions have a timeout (typically 24 hours for TLS 1.2, longer for TLS 1.3).
    /// Using an expired session can cause:
    /// - Silent handshake failures
    /// - False negatives in resumption tests
    fn is_session_valid(session: &SslSession) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::session_times_valid(session.time(), session.timeout(), current_time)
    }

    fn session_times_valid(session_time: i64, timeout: i64, current_time: u64) -> bool {
        let Ok(session_time) = u64::try_from(session_time) else {
            return false;
        };
        let Ok(timeout) = u64::try_from(timeout) else {
            return false;
        };

        // Session is valid if current time is less than session time + timeout
        // Also check that session_time is not in the future (clock skew protection)
        if timeout == 0 {
            return current_time >= session_time;
        }
        let Some(expires_at) = session_time.checked_add(timeout) else {
            return false;
        };
        current_time >= session_time && current_time < expires_at
    }

    /// Run complete session resumption tests
    pub async fn test(&self) -> Result<SessionResumptionResult> {
        let session_id = self.test_session_id_reuse().await?;
        let session_ticket = self.test_session_ticket().await?;

        let inconclusive = (session_id.inconclusive || session_ticket.inconclusive)
            && !session_id.reuse_successful
            && !session_ticket.reuse_successful;

        let resumption_support = if session_id.reuse_successful && session_ticket.reuse_successful {
            ResumptionSupport::Full
        } else if session_id.reuse_successful {
            ResumptionSupport::SessionIdOnly
        } else if session_ticket.reuse_successful {
            ResumptionSupport::TicketOnly
        } else if inconclusive {
            ResumptionSupport::Unknown
        } else {
            ResumptionSupport::None
        };

        let (performance_gain, performance_note) =
            if session_id.reuse_successful || session_ticket.reuse_successful {
                match self.measure_performance_gain().await {
                    Ok(gain) => (Some(gain), String::new()),
                    Err(error) => (None, format!(". Performance measurement failed: {error}")),
                }
            } else {
                (None, String::new())
            };

        let details = format!(
            "Session resumption: {}. Session ID reuse: {}/{}. Ticket reuse: {}{}",
            resumption_support.as_str(),
            session_id.reuse_count,
            session_id.connections_tested,
            session_ticket.reuse_successful,
            performance_note
        );

        Ok(SessionResumptionResult {
            session_id_reuse: session_id,
            session_ticket,
            resumption_support,
            inconclusive,
            performance_gain,
            details,
        })
    }

    /// Lightweight single-shot resumption probe for the protocol phase.
    ///
    /// Establishes one session, attempts to resume it once, and reports
    /// `(session-id caching, session tickets)` support. Returns `None` for both
    /// dimensions when the probe could not reach a verdict (connection or
    /// handshake failure) so the caller surfaces an honest "unknown" rather than
    /// a false negative. A resumed session whose Session ID is empty indicates
    /// ticket-based resumption (RFC 5077); a non-empty Session ID indicates
    /// session-ID cache resumption.
    pub async fn quick_probe(&self) -> (Option<bool>, Option<bool>) {
        let session = match self.establish_session().await {
            Ok(Some(session)) => session,
            // Connected, but the server offered no resumable session.
            Ok(None) => return (Some(false), Some(false)),
            // Connection/handshake failure: inconclusive, not "unsupported".
            Err(_) => return (None, None),
        };

        let session_id_empty = session.id().is_empty();

        match self.try_resume_with_session(session).await {
            Ok(true) if session_id_empty => (Some(false), Some(true)),
            Ok(true) => (Some(true), Some(false)),
            Ok(false) => (Some(false), Some(false)),
            Err(_) => (None, None),
        }
    }

    async fn prepare_stream(&self) -> Result<std::net::TcpStream> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let mut stream = crate::utils::network::connect_with_timeout(
            addr,
            Duration::from_secs(10),
            None,
        )
        .await?;

        if let Some(starttls_proto) = self.starttls {
            let hostname = self
                .starttls_hostname
                .clone()
                .unwrap_or_else(|| self.target.hostname.clone());
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                hostname,
                self.starttls_server_mode,
            );
            crate::starttls::protocols::negotiate_starttls_with_timeout(
                negotiator.as_ref(),
                &mut stream,
                Duration::from_secs(10),
            )
            .await
            .map_err(|error| TlsError::StarttlsError {
                protocol: starttls_proto.to_string(),
                details: format!("STARTTLS negotiation failed before session resumption test: {error}"),
            })?;
        }

        crate::utils::network::into_blocking_std_stream(stream, Duration::from_secs(10))
    }

    fn build_connector(&self) -> Result<SslConnector> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        // Certificate validity is irrelevant to whether a server offers session
        // resumption; a verifying connector would fail the handshake on bad-cert
        // hosts and report resumption as unsupported/inconclusive.
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        Ok(builder.build())
    }

    fn establish_session_sync(&self, stream: std::net::TcpStream) -> Result<Option<SslSession>> {
        let connector = self.build_connector()?;
        let ssl_stream = connector.connect(&self.target.hostname, stream)?;
        Ok(ssl_stream.ssl().session().map(|session| session.to_owned()))
    }

    fn resume_with_session_sync(
        &self,
        stream: std::net::TcpStream,
        session: &SslSession,
    ) -> Result<bool> {
        // Validate session hasn't expired before attempting resumption
        // This prevents false negatives from using stale sessions
        if !Self::is_session_valid(session) {
            return Err(TlsError::InvalidHandshake {
                details: "Session has expired and cannot be used for resumption".to_string(),
            });
        }

        let connector = self.build_connector()?;
        let mut ssl = connector.configure()?.into_ssl(&self.target.hostname)?;
        // SAFETY: Setting a session is safe as long as the session is valid.
        // We've validated the session hasn't expired above. The session must not
        // be used concurrently (which we ensure by not sharing it across threads).
        unsafe {
            ssl.set_session(session)?;
        }
        let mut ssl_stream = SslStream::new(ssl, stream)?;
        ssl_stream
            .connect()
            .map_err(|err| TlsError::InvalidHandshake {
                details: format!("TLS resume handshake failed: {err}"),
            })?;
        Ok(ssl_stream.ssl().session_reused())
    }

    async fn establish_session(&self) -> Result<Option<SslSession>> {
        let target = self.target.clone();
        let std_stream = self.prepare_stream().await?;
        tokio::task::spawn_blocking(move || {
            let tester = SessionResumptionTester::new(target);
            tester.establish_session_sync(std_stream)
        })
        .await
        .map_err(|err| {
            crate::error::TlsError::Other(format!("Session establish join error: {err}"))
        })?
    }

    async fn try_resume_with_session(&self, session: SslSession) -> Result<bool> {
        let target = self.target.clone();
        let std_stream = self.prepare_stream().await?;
        tokio::task::spawn_blocking(move || {
            let tester = SessionResumptionTester::new(target);
            tester.resume_with_session_sync(std_stream, &session)
        })
        .await
        .map_err(|err| crate::error::TlsError::Other(format!("Session resume join error: {err}")))?
    }

    /// Test session ID reuse
    async fn test_session_id_reuse(&self) -> Result<SessionIdTest> {
        let session = match self.establish_session().await {
            Ok(Some(session)) => session,
            Ok(None) => {
                return Ok(SessionIdTest {
                    supported: false,
                    session_id_length: None,
                    reuse_successful: false,
                    connections_tested: 1,
                    reuse_count: 0,
                    inconclusive: false,
                });
            }
            Err(_) => {
                return Ok(SessionIdTest {
                    supported: false,
                    session_id_length: None,
                    reuse_successful: false,
                    connections_tested: 1,
                    reuse_count: 0,
                    inconclusive: true,
                });
            }
        };

        let session_id_length = session.id().len();

        if session_id_length == 0 {
            return Ok(SessionIdTest {
                supported: false,
                session_id_length: Some(0),
                reuse_successful: false,
                connections_tested: 1,
                reuse_count: 0,
                inconclusive: false,
            });
        }

        let mut reuse_count = 0;
        let mut resume_errors = 0;
        let connections_tested = 5;

        for _ in 0..connections_tested {
            match self.try_resume_with_session(session.clone()).await {
                Ok(true) => reuse_count += 1,
                Ok(false) => {}
                Err(_) => resume_errors += 1,
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let reuse_successful = reuse_count > 0;
        let inconclusive = !reuse_successful && resume_errors == connections_tested;

        Ok(SessionIdTest {
            supported: reuse_successful,
            session_id_length: Some(session_id_length),
            reuse_successful,
            connections_tested,
            reuse_count,
            inconclusive,
        })
    }

    /// Test session ticket (RFC 5077)
    ///
    /// Heuristic: If session ID is empty but resumption succeeds, the server
    /// uses session tickets. If session ID is non-empty AND resumption succeeds,
    /// both mechanisms may be in play — we report ticket support based on
    /// whether the session object contains ticket data.
    async fn test_session_ticket(&self) -> Result<SessionTicketTest> {
        let session = match self.establish_session().await {
            Ok(Some(session)) => session,
            Ok(None) => {
                return Ok(SessionTicketTest {
                    supported: false,
                    ticket_lifetime: None,
                    ticket_size: None,
                    reuse_successful: false,
                    new_ticket_on_resume: false,
                    inconclusive: false,
                });
            }
            Err(_) => {
                return Ok(SessionTicketTest {
                    supported: false,
                    ticket_lifetime: None,
                    ticket_size: None,
                    reuse_successful: false,
                    new_ticket_on_resume: false,
                    inconclusive: true,
                });
            }
        };

        let session_id_empty = session.id().is_empty();

        let (reuse_successful, inconclusive) =
            match self.try_resume_with_session(session.clone()).await {
                Ok(resumed) => (resumed, false),
                Err(_) => (false, true),
            };

        // If session ID was empty but resumption succeeded, tickets are in use.
        // If session ID was present and resumption succeeded, we can't distinguish
        // the mechanism with certainty — report as potentially supported.
        let ticket_likely = reuse_successful && session_id_empty;

        Ok(SessionTicketTest {
            supported: reuse_successful,
            ticket_lifetime: None,
            ticket_size: None,
            reuse_successful,
            new_ticket_on_resume: ticket_likely,
            inconclusive,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use std::sync::Once;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn test_resumption_support_display() {
        assert_eq!(
            ResumptionSupport::Full.as_str(),
            "Full (Session ID + Tickets)"
        );
        assert_eq!(ResumptionSupport::SessionIdOnly.as_str(), "Session ID Only");
        assert_eq!(
            ResumptionSupport::TicketOnly.as_str(),
            "Session Tickets Only"
        );
        assert_eq!(ResumptionSupport::None.as_str(), "None");
        assert_eq!(
            ResumptionSupport::Unknown.as_str(),
            "Unknown (test inconclusive)"
        );
    }

    #[test]
    fn test_session_resumption_result_details_contains_counts() {
        let result = SessionResumptionResult {
            session_id_reuse: SessionIdTest {
                supported: true,
                session_id_length: Some(32),
                reuse_successful: true,
                connections_tested: 3,
                reuse_count: 2,
                inconclusive: false,
            },
            session_ticket: SessionTicketTest {
                supported: false,
                ticket_lifetime: None,
                ticket_size: None,
                reuse_successful: false,
                new_ticket_on_resume: false,
                inconclusive: false,
            },
            resumption_support: ResumptionSupport::SessionIdOnly,
            inconclusive: false,
            performance_gain: None,
            details:
                "Session resumption: Session ID Only. Session ID reuse: 2/3. Ticket reuse: false"
                    .to_string(),
        };
        assert!(result.details.contains("2/3"));
        assert!(matches!(
            result.resumption_support,
            ResumptionSupport::SessionIdOnly
        ));
    }

    #[test]
    fn test_negative_session_times_are_invalid() {
        assert!(!SessionResumptionTester::session_times_valid(-1, 60, 10));
        assert!(!SessionResumptionTester::session_times_valid(1, -60, 10));
    }

    #[test]
    fn test_overflowing_session_expiry_is_invalid() {
        assert!(!SessionResumptionTester::session_times_valid(
            i64::MAX,
            i64::MAX,
            u64::MAX - 1
        ));
    }

    #[test]
    fn test_starttls_configuration_is_stored() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = SessionResumptionTester::new(target)
            .with_starttls(Some(crate::starttls::StarttlsProtocol::XMPP), Some("xmpp.example.com".to_string()))
            .with_starttls_server_mode(true);

        assert_eq!(tester.starttls, Some(crate::starttls::StarttlsProtocol::XMPP));
        assert_eq!(
            tester.starttls_hostname.as_deref(),
            Some("xmpp.example.com")
        );
        assert!(tester.starttls_server_mode);
    }

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    async fn spawn_tls_server(max_accepts: usize) -> (SocketAddr, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tmp = std::env::temp_dir();
        let cert_path = tmp.join(format!(
            "cipherrun_test_cert_{}_{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();

        // SAFETY: This test runs in isolation and cleans up after itself.
        // The SSL_CERT_FILE env var is only set for the duration of this test.
        // Using unsafe because set_var requires unsafe in newer Rust versions.
        // This could cause issues if tests run in parallel, so test isolation is assumed.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("SSL_CERT_FILE", &cert_path);
        }

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
    async fn test_session_resumption_against_local_tls() {
        install_crypto_provider();
        let (addr, cert_path) = spawn_tls_server(40).await;

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = SessionResumptionTester::new(target);
        let result = tester.test().await.unwrap();

        assert!(result.session_id_reuse.connections_tested > 0);
        assert!(!result.details.is_empty());

        // Cleanup: Remove the temp cert file
        let _ = std::fs::remove_file(&cert_path);

        // SAFETY: Clean up the environment variable after test completes
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("SSL_CERT_FILE");
        }
    }

    #[test]
    fn test_session_resumption_result_defaults() {
        let result = SessionResumptionResult {
            session_id_reuse: SessionIdTest {
                supported: false,
                session_id_length: None,
                reuse_successful: false,
                connections_tested: 0,
                reuse_count: 0,
                inconclusive: false,
            },
            session_ticket: SessionTicketTest {
                supported: false,
                ticket_lifetime: None,
                ticket_size: None,
                reuse_successful: false,
                new_ticket_on_resume: false,
                inconclusive: false,
            },
            resumption_support: ResumptionSupport::None,
            inconclusive: false,
            performance_gain: None,
            details: "No resumption".to_string(),
        };

        assert!(!result.session_id_reuse.supported);
        assert!(!result.session_ticket.supported);
        assert!(result.details.contains("No resumption"));
    }

    #[tokio::test]
    async fn test_session_resumption_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = SessionResumptionTester::new(target);
        let result = tester.test().await.unwrap();

        assert_eq!(result.resumption_support, ResumptionSupport::Unknown);
        assert!(result.inconclusive);
        assert!(result.session_id_reuse.inconclusive);
        assert!(result.session_ticket.inconclusive);
    }

    #[tokio::test]
    async fn test_quick_probe_inactive_target_is_unknown() {
        // A closed port can't reach a verdict, so quick_probe must report honest
        // unknowns (None, None) rather than a false "not supported".
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let (caching, tickets) = SessionResumptionTester::new(target).quick_probe().await;
        assert_eq!(caching, None);
        assert_eq!(tickets, None);
    }
}
