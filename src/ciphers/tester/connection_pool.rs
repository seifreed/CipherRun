use crate::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[allow(dead_code)]
pub(crate) struct TlsConnectionPool {
    pool: Arc<Mutex<Vec<TcpStream>>>,
    addr: SocketAddr,
    max_size: usize,
    connect_timeout: Duration,
    retry_config: Option<crate::utils::retry::RetryConfig>,
}

impl TlsConnectionPool {
    pub(crate) fn new(
        addr: SocketAddr,
        max_size: usize,
        connect_timeout: Duration,
        retry_config: Option<crate::utils::retry::RetryConfig>,
    ) -> Self {
        Self {
            pool: Arc::new(Mutex::new(Vec::with_capacity(max_size))),
            addr,
            max_size,
            connect_timeout,
            retry_config,
        }
    }

    pub(crate) async fn acquire(&self) -> Result<TcpStream> {
        {
            let mut pool = self.pool.lock().await;
            if let Some(stream) = pool.pop() {
                tracing::trace!("Connection pool hit (size: {})", pool.len());
                return Ok(stream);
            }
        }

        tracing::trace!(
            "Connection pool miss, establishing new connection to {}",
            self.addr
        );
        crate::utils::network::connect_with_timeout(
            self.addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        .map_err(|e| crate::TlsError::Other(format!("Connection failed: {}", e)).into())
    }

    #[allow(dead_code)]
    pub(crate) async fn release(&self, stream: TcpStream) {
        let mut pool = self.pool.lock().await;
        if pool.len() < self.max_size {
            pool.push(stream);
            tracing::trace!("Connection returned to the pool (size: {})", pool.len());
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn size(&self) -> usize {
        self.pool.lock().await.len()
    }
}
