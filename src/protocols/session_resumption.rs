// Session Resumption Testing - Complete Session Resume Analysis
// Tests session IDs, session tickets (RFC 5077), and resumption behavior

mod model;
mod performance;

pub use model::{
    ResumptionSupport, SessionIdTest, SessionResumptionResult, SessionTicketTest,
};

use crate::Result;
use crate::utils::network::Target;
use openssl::ssl::{SslConnector, SslMethod, SslSession, SslSessionCacheMode, SslStream};
use std::time::Duration;

/// Session resumption tester
pub struct SessionResumptionTester {
    target: Target,
}

impl SessionResumptionTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Run complete session resumption tests
    pub async fn test(&self) -> Result<SessionResumptionResult> {
        let session_id = self.test_session_id_reuse().await?;
        let session_ticket = self.test_session_ticket().await?;

        let resumption_support = if session_id.reuse_successful && session_ticket.reuse_successful {
            ResumptionSupport::Full
        } else if session_id.reuse_successful {
            ResumptionSupport::SessionIdOnly
        } else if session_ticket.reuse_successful {
            ResumptionSupport::TicketOnly
        } else {
            ResumptionSupport::None
        };

        let performance_gain = if session_id.reuse_successful || session_ticket.reuse_successful {
            self.measure_performance_gain().await.ok()
        } else {
            None
        };

        let details = format!(
            "Session resumption: {}. Session ID reuse: {}/{}. Ticket reuse: {}",
            resumption_support.as_str(),
            session_id.reuse_count,
            session_id.connections_tested,
            session_ticket.reuse_successful
        );

        Ok(SessionResumptionResult {
            session_id_reuse: session_id,
            session_ticket,
            resumption_support,
            performance_gain,
            details,
        })
    }

    fn build_connector(&self) -> Result<SslConnector> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        Ok(builder.build())
    }

    fn establish_session_sync(&self) -> Result<Option<SslSession>> {
        use std::net::TcpStream as StdTcpStream;

        let addr = self.target.socket_addrs()[0];
        let stream = StdTcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        stream.set_nonblocking(false)?;

        let connector = self.build_connector()?;
        let ssl_stream = connector.connect(&self.target.hostname, stream)?;
        Ok(ssl_stream.ssl().session().map(|session| session.to_owned()))
    }

    fn resume_with_session_sync(&self, session: &SslSession) -> Result<bool> {
        use std::net::TcpStream as StdTcpStream;

        let addr = self.target.socket_addrs()[0];
        let stream = StdTcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        stream.set_nonblocking(false)?;

        let connector = self.build_connector()?;
        let mut ssl = connector.configure()?.into_ssl(&self.target.hostname)?;
        unsafe {
            ssl.set_session(session)?;
        }
        let mut ssl_stream = SslStream::new(ssl, stream)?;
        ssl_stream
            .connect()
            .map_err(|err| anyhow::anyhow!("TLS resume handshake failed: {err}"))?;
        Ok(ssl_stream.ssl().session_reused())
    }

    async fn establish_session(&self) -> Result<Option<SslSession>> {
        let target = self.target.clone();
        tokio::task::spawn_blocking(move || {
            let tester = SessionResumptionTester { target };
            tester.establish_session_sync()
        })
        .await
        .map_err(|err| anyhow::anyhow!("Session establish join error: {err}"))?
    }

    async fn try_resume_with_session(&self, session: SslSession) -> Result<bool> {
        let target = self.target.clone();
        tokio::task::spawn_blocking(move || {
            let tester = SessionResumptionTester { target };
            tester.resume_with_session_sync(&session)
        })
        .await
        .map_err(|err| anyhow::anyhow!("Session resume join error: {err}"))?
    }

    /// Test session ID reuse
    async fn test_session_id_reuse(&self) -> Result<SessionIdTest> {
        let Some(session) = self.establish_session().await? else {
            return Ok(SessionIdTest {
                supported: false,
                session_id_length: None,
                reuse_successful: false,
                connections_tested: 1,
                reuse_count: 0,
            });
        };

        let session_id_length = session.id().len();

        if session_id_length == 0 {
            return Ok(SessionIdTest {
                supported: false,
                session_id_length: Some(0),
                reuse_successful: false,
                connections_tested: 1,
                reuse_count: 0,
            });
        }

        let mut reuse_count = 0;
        let connections_tested = 5;

        for _ in 0..connections_tested {
            if let Ok(resumed) = self.try_resume_with_session(session.clone()).await
                && resumed
            {
                reuse_count += 1;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let reuse_successful = reuse_count > 0;

        Ok(SessionIdTest {
            supported: reuse_successful,
            session_id_length: Some(session_id_length),
            reuse_successful,
            connections_tested,
            reuse_count,
        })
    }

    /// Test session ticket (RFC 5077)
    async fn test_session_ticket(&self) -> Result<SessionTicketTest> {
        let Some(session) = self.establish_session().await? else {
            return Ok(SessionTicketTest {
                supported: false,
                ticket_lifetime: None,
                ticket_size: None,
                reuse_successful: false,
                new_ticket_on_resume: false,
            });
        };

        let ticket_hint = session.id().is_empty();
        let reuse_successful = if ticket_hint {
            self.try_resume_with_session(session.clone())
                .await
                .unwrap_or(false)
        } else {
            false
        };

        Ok(SessionTicketTest {
            supported: reuse_successful,
            ticket_lifetime: None,
            ticket_size: None,
            reuse_successful,
            new_ticket_on_resume: false,
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
            },
            session_ticket: SessionTicketTest {
                supported: false,
                ticket_lifetime: None,
                ticket_size: None,
                reuse_successful: false,
                new_ticket_on_resume: false,
            },
            resumption_support: ResumptionSupport::SessionIdOnly,
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
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
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

        let _ = std::fs::remove_file(cert_path);
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
            },
            session_ticket: SessionTicketTest {
                supported: false,
                ticket_lifetime: None,
                ticket_size: None,
                reuse_successful: false,
                new_ticket_on_resume: false,
            },
            resumption_support: ResumptionSupport::None,
            performance_gain: None,
            details: "No resumption".to_string(),
        };

        assert!(!result.session_id_reuse.supported);
        assert!(!result.session_ticket.supported);
        assert!(result.details.contains("No resumption"));
    }
}
