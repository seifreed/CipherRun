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

#[cfg(test)]
mod tests {
    use super::TlsConnectionPool;
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn acquire_connects_to_the_configured_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let pool = TlsConnectionPool::new(address, 1, Duration::from_secs(1), None);

        let stream = pool.acquire().await.unwrap();

        assert_eq!(stream.peer_addr().unwrap(), address);
    }

    #[tokio::test]
    async fn acquire_maps_connection_errors() {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        drop(listener);
        let pool = TlsConnectionPool::new(address, 1, Duration::from_secs(1), None);

        let error = pool.acquire().await.unwrap_err();

        assert!(error.to_string().contains("Connection failed:"));
    }
}
