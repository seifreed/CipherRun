// Session Resumption Testing - Complete Session Resume Analysis
// Tests session IDs, session tickets (RFC 5077), and resumption behavior

use crate::utils::network::Target;
use crate::{Result, tls_bail};
use openssl::ssl::{SslConnector, SslMethod, SslSessionCacheMode};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Session resumption test results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResumptionResult {
    pub session_id_reuse: SessionIdTest,
    pub session_ticket: SessionTicketTest,
    pub resumption_support: ResumptionSupport,
    pub performance_gain: Option<f64>, // Percentage improvement
    pub details: String,
}

/// Session ID reuse test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIdTest {
    pub supported: bool,
    pub session_id_length: Option<usize>,
    pub reuse_successful: bool,
    pub connections_tested: usize,
    pub reuse_count: usize,
}

/// Session ticket (RFC 5077) test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicketTest {
    pub supported: bool,
    pub ticket_lifetime: Option<u32>, // seconds
    pub ticket_size: Option<usize>,
    pub reuse_successful: bool,
    pub new_ticket_on_resume: bool,
}

/// Resumption support level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResumptionSupport {
    Full,          // Both session ID and tickets
    SessionIdOnly, // Only session ID
    TicketOnly,    // Only session tickets
    None,          // No resumption support
}

impl ResumptionSupport {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResumptionSupport::Full => "Full (Session ID + Tickets)",
            ResumptionSupport::SessionIdOnly => "Session ID Only",
            ResumptionSupport::TicketOnly => "Session Tickets Only",
            ResumptionSupport::None => "None",
        }
    }
}

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

        let resumption_support = if session_id.supported && session_ticket.supported {
            ResumptionSupport::Full
        } else if session_id.supported {
            ResumptionSupport::SessionIdOnly
        } else if session_ticket.supported {
            ResumptionSupport::TicketOnly
        } else {
            ResumptionSupport::None
        };

        let performance_gain = if session_id.reuse_successful || session_ticket.reuse_successful {
            Some(self.measure_performance_gain().await.unwrap_or(0.0))
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

    /// Test session ID reuse
    async fn test_session_id_reuse(&self) -> Result<SessionIdTest> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        // First connection - establish session
        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Enable session caching
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        let connector = builder.build();

        // Initial connection
        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        // Get session and extract data before dropping
        let (session_id_length, has_session_id) = {
            if let Some(session) = ssl_stream.ssl().session() {
                let len = session.id().len();
                (len, len > 0)
            } else {
                tls_bail!("No session established");
            }
        };

        // Close first connection
        drop(ssl_stream);

        if !has_session_id {
            return Ok(SessionIdTest {
                supported: false,
                session_id_length: None,
                reuse_successful: false,
                connections_tested: 1,
                reuse_count: 0,
            });
        }

        // Try to resume with session - multiple attempts
        let mut reuse_count = 0;
        let connections_tested = 5;

        for _ in 0..connections_tested {
            if let Ok(resumed) = self.try_resume_with_session().await
                && resumed
            {
                reuse_count += 1;
            }
            // Small delay between attempts
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let reuse_successful = reuse_count > 0;

        Ok(SessionIdTest {
            supported: true,
            session_id_length: Some(session_id_length),
            reuse_successful,
            connections_tested,
            reuse_count,
        })
    }

    async fn try_resume_with_session(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                // Check if session was reused
                let reused = ssl_stream.ssl().session_reused();
                Ok(reused)
            }
            Err(_) => Ok(false),
        }
    }

    /// Test session ticket (RFC 5077)
    async fn test_session_ticket(&self) -> Result<SessionTicketTest> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        // First connection - check for ticket
        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Enable session tickets
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        let connector = builder.build();

        let ssl_stream = connector.connect(&self.target.hostname, std_stream)?;

        // Check if we got a session ticket
        // Session ticket is indicated by having a session but no session ID
        let has_ticket = {
            if let Some(session) = ssl_stream.ssl().session() {
                session.id().is_empty()
            } else {
                false
            }
        };

        // Close first connection
        drop(ssl_stream);

        if !has_ticket {
            return Ok(SessionTicketTest {
                supported: false,
                ticket_lifetime: None,
                ticket_size: None,
                reuse_successful: false,
                new_ticket_on_resume: false,
            });
        }

        // Try to resume with ticket
        let reuse_successful = self.try_resume_with_ticket().await.unwrap_or(false);

        Ok(SessionTicketTest {
            supported: true,
            ticket_lifetime: None, // Can't get ticket lifetime from rust-openssl
            ticket_size: None,     // Can't easily get ticket size from rust-openssl
            reuse_successful,
            new_ticket_on_resume: false, // Would need to check on resume
        })
    }

    async fn try_resume_with_ticket(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                let reused = ssl_stream.ssl().session_reused();
                Ok(reused)
            }
            Err(_) => Ok(false),
        }
    }

    /// Measure performance gain from session resumption
    async fn measure_performance_gain(&self) -> Result<f64> {
        use std::time::Instant;

        // Measure full handshake time
        let full_handshake_times: Vec<f64> = (0..5)
            .filter_map(|_| {
                let start = Instant::now();
                if self.perform_full_handshake_sync().is_ok() {
                    Some(start.elapsed().as_secs_f64())
                } else {
                    None
                }
            })
            .collect();

        if full_handshake_times.is_empty() {
            return Ok(0.0);
        }

        let avg_full = full_handshake_times.iter().sum::<f64>() / full_handshake_times.len() as f64;

        // Measure resumed handshake time
        let resumed_handshake_times: Vec<f64> = (0..5)
            .filter_map(|_| {
                let start = Instant::now();
                if self.perform_resumed_handshake_sync().is_ok() {
                    Some(start.elapsed().as_secs_f64())
                } else {
                    None
                }
            })
            .collect();

        if resumed_handshake_times.is_empty() {
            return Ok(0.0);
        }

        let avg_resumed =
            resumed_handshake_times.iter().sum::<f64>() / resumed_handshake_times.len() as f64;

        // Calculate improvement percentage
        let improvement = if avg_full > 0.0 {
            ((avg_full - avg_resumed) / avg_full) * 100.0
        } else {
            0.0
        };

        Ok(improvement)
    }

    fn perform_full_handshake_sync(&self) -> Result<()> {
        // Synchronous version for timing
        use std::net::TcpStream as StdTcpStream;

        let addr = self.target.socket_addrs()[0];
        let stream = StdTcpStream::connect(addr)?;

        let builder = SslConnector::builder(SslMethod::tls())?;
        let connector = builder.build();

        let _ssl_stream = connector.connect(&self.target.hostname, stream)?;

        Ok(())
    }

    fn perform_resumed_handshake_sync(&self) -> Result<()> {
        // Synchronous version for timing
        use std::net::TcpStream as StdTcpStream;

        let addr = self.target.socket_addrs()[0];

        // Establish initial connection
        let stream1 = StdTcpStream::connect(addr)?;
        let mut builder1 = SslConnector::builder(SslMethod::tls())?;
        builder1.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        let connector1 = builder1.build();
        let ssl_stream1 = connector1.connect(&self.target.hostname, stream1)?;

        // Get session
        let _session = ssl_stream1
            .ssl()
            .session()
            .ok_or_else(|| anyhow::anyhow!("No session"))?;

        drop(ssl_stream1);

        // Resume connection
        let stream2 = StdTcpStream::connect(addr)?;
        let mut builder2 = SslConnector::builder(SslMethod::tls())?;
        builder2.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        let connector2 = builder2.build();
        let _ssl_stream2 = connector2.connect(&self.target.hostname, stream2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
