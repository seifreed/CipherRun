#[derive(Debug, Clone)]
pub struct ScanRequestConnection {
    pub socket_timeout: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub sleep: Option<u64>,
    pub max_retries: usize,
    pub retry_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub no_retry: bool,
}

impl Default for ScanRequestConnection {
    fn default() -> Self {
        Self {
            socket_timeout: None,
            connect_timeout: None,
            sleep: None,
            max_retries: 3,
            retry_backoff_ms: 100,
            max_backoff_ms: 5000,
            no_retry: false,
        }
    }
}
