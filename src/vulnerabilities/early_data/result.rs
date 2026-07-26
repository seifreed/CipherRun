/// Information about early data size from server.
#[derive(Debug, Clone)]
pub struct EarlyDataSizeInfo {
    /// Whether TLS 1.3 is supported.
    pub tls13_supported: bool,
    /// Whether early_data extension was advertised.
    pub early_data_supported: bool,
    /// Maximum early data size in bytes, if known.
    pub max_early_data_size: Option<u32>,
    /// Whether the value was estimated heuristically instead of parsed from a ticket.
    pub is_estimated: bool,
    /// Whether support could not be determined due to an operational failure.
    pub inconclusive: bool,
}

/// Result of 0-RTT replay attack testing.
#[derive(Debug, Clone)]
pub struct ReplayTestResult {
    /// Whether the test was actually performed.
    pub tested: bool,
    /// Whether the server is vulnerable to replay.
    pub vulnerable: bool,
    /// Whether the result is inconclusive because the test could not be performed.
    pub inconclusive: bool,
    /// Details about the test result.
    pub details: String,
}

/// 0-RTT / Early Data test result.
#[derive(Debug, Clone)]
pub struct EarlyDataTestResult {
    pub vulnerable: bool,
    pub supports_early_data: bool,
    pub accepts_replayed_data: bool,
    pub max_early_data_size: Option<u32>,
    pub issues: Vec<String>,
    pub details: String,
    pub inconclusive: bool,
}
