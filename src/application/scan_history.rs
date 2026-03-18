use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ScanHistoryQuery {
    pub hostname: String,
    pub port: u16,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct ScanHistoryEntry {
    pub scan_id: u64,
    pub timestamp: DateTime<Utc>,
    pub grade: Option<String>,
    pub score: Option<u8>,
    pub duration_ms: Option<u64>,
}
