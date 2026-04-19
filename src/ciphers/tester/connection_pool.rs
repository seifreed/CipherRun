use crate::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// A connection pool for cipher testing.
///
/// IMPORTANT: Each cipher test requires a fresh TCP connection because the
/// TLS handshake probe leaves the stream in a post-handshake state. Pooled
/// connections are NEVER reused across cipher tests — every `acquire()` call
/// creates a new connection. The pool exists solely to manage connection
/// creation parameters (address, timeouts, retry config) in one place.
pub(crate) struct TlsConnectionPool {
    addr: SocketAddr,
    connect_timeout: Duration,
    retry_config: Option<crate::utils::retry::RetryConfig>,
}

impl TlsConnectionPool {
    pub(crate) fn new(
        addr: SocketAddr,
        _max_size: usize,
        connect_timeout: Duration,
        retry_config: Option<crate::utils::retry::RetryConfig>,
    ) -> Self {
        Self {
            addr,
            connect_timeout,
            retry_config,
        }
    }

    pub(crate) async fn acquire(&self) -> Result<TcpStream> {
        crate::utils::network::connect_with_timeout(
            self.addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        .map_err(|e| crate::TlsError::Other(format!("Connection failed: {}", e)))
    }
}
