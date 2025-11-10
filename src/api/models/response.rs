// API Response Models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

/// Scan response (returned when creating a scan)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanResponse {
    /// Unique scan ID
    pub scan_id: String,

    /// Current scan status
    pub status: ScanStatus,

    /// Target being scanned
    pub target: String,

    /// WebSocket URL for real-time progress
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_url: Option<String>,

    /// When the scan was queued
    pub queued_at: DateTime<Utc>,

    /// Estimated completion time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_completion: Option<DateTime<Utc>>,
}

/// Scan status response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanStatusResponse {
    /// Unique scan ID
    pub scan_id: String,

    /// Current status
    pub status: ScanStatus,

    /// Progress percentage (0-100)
    pub progress: u8,

    /// Current stage being executed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_stage: Option<String>,

    /// Estimated seconds until completion
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<u64>,

    /// When scan started
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    /// When scan completed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Link to results (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results_url: Option<String>,
}

/// Scan status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    /// Scan is queued waiting for execution
    Queued,

    /// Scan is currently running
    Running,

    /// Scan completed successfully
    Completed,

    /// Scan failed with error
    Failed,

    /// Scan was cancelled
    Cancelled,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    /// Service status
    pub status: String,

    /// Service version
    pub version: String,

    /// Uptime in seconds
    pub uptime_seconds: u64,

    /// Current number of active scans
    pub active_scans: usize,

    /// Queued scans
    pub queued_scans: usize,

    /// Database connection status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
}

/// Statistics response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StatsResponse {
    /// Total scans performed
    pub total_scans: u64,

    /// Completed scans
    pub completed_scans: u64,

    /// Failed scans
    pub failed_scans: u64,

    /// Average scan duration in seconds
    pub avg_scan_duration_seconds: f64,

    /// Scans in last 24 hours
    pub scans_last_24h: u64,

    /// Scans in last 7 days
    pub scans_last_7d: u64,

    /// Most scanned domains (top 10)
    pub top_domains: Vec<DomainStats>,

    /// Current API usage statistics
    pub api_usage: ApiUsageStats,
}

/// Domain statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DomainStats {
    /// Domain name
    pub domain: String,

    /// Number of scans
    pub scan_count: u64,

    /// Last scan time
    pub last_scan: DateTime<Utc>,
}

/// API usage statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiUsageStats {
    /// Requests in last hour
    pub requests_last_hour: u64,

    /// Requests in last day
    pub requests_last_day: u64,

    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
}

/// Certificate list response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertificateListResponse {
    /// Total count of certificates
    pub total: usize,

    /// Current page offset
    pub offset: usize,

    /// Page size limit
    pub limit: usize,

    /// Certificate summaries
    pub certificates: Vec<CertificateSummary>,
}

/// Certificate summary
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertificateSummary {
    /// SHA-256 fingerprint
    pub fingerprint: String,

    /// Subject common name
    pub common_name: String,

    /// Subject alternative names
    pub san: Vec<String>,

    /// Issuer
    pub issuer: String,

    /// Valid from
    pub valid_from: DateTime<Utc>,

    /// Valid until
    pub valid_until: DateTime<Utc>,

    /// Days until expiry
    pub days_until_expiry: i64,

    /// Certificate is expired
    pub is_expired: bool,

    /// Certificate is expiring soon (< 30 days)
    pub is_expiring_soon: bool,

    /// Associated hostnames
    pub hostnames: Vec<String>,
}

/// Policy response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyResponse {
    /// Policy ID
    pub id: String,

    /// Policy name
    pub name: String,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Rules in YAML format
    pub rules: String,

    /// Enabled status
    pub enabled: bool,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyEvaluationResponse {
    /// Policy ID
    pub policy_id: String,

    /// Policy name
    pub policy_name: String,

    /// Target evaluated
    pub target: String,

    /// Overall compliance status
    pub compliant: bool,

    /// Individual check results
    pub checks: Vec<PolicyCheckResult>,

    /// Evaluation timestamp
    pub evaluated_at: DateTime<Utc>,

    /// Scan used for evaluation
    pub scan_id: String,
}

/// Individual policy check result
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyCheckResult {
    /// Check name
    pub check: String,

    /// Check passed
    pub passed: bool,

    /// Severity level
    pub severity: String,

    /// Failure message if not passed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Expected value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,

    /// Actual value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

/// Scan history response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanHistoryResponse {
    /// Domain
    pub domain: String,

    /// Port
    pub port: u16,

    /// Total scans in history
    pub total_scans: usize,

    /// Historical scan records
    pub scans: Vec<ScanHistoryItem>,
}

/// Individual scan history item
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanHistoryItem {
    /// Scan ID
    pub scan_id: u64,

    /// Scan timestamp
    pub timestamp: DateTime<Utc>,

    /// Overall grade
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,

    /// Overall score
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,

    /// Scan duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Historical scan record
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HistoricalScan {
    /// Scan ID
    pub scan_id: String,

    /// Scan timestamp
    pub timestamp: DateTime<Utc>,

    /// Overall grade
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,

    /// Overall score
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,

    /// Scan duration in milliseconds
    pub duration_ms: u64,

    /// Number of vulnerabilities found
    pub vulnerability_count: usize,

    /// Link to full results
    pub results_url: String,
}

/// WebSocket progress message
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProgressMessage {
    /// Message type
    pub msg_type: String,

    /// Scan ID
    pub scan_id: String,

    /// Progress percentage (0-100)
    pub progress: u8,

    /// Current stage
    pub stage: String,

    /// Stage details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl ProgressMessage {
    /// Create a new progress message
    pub fn new(scan_id: String, progress: u8, stage: String) -> Self {
        Self {
            msg_type: "progress".to_string(),
            scan_id,
            progress,
            stage,
            details: None,
            timestamp: Utc::now(),
        }
    }

    /// Create a completion message
    pub fn completed(scan_id: String) -> Self {
        Self {
            msg_type: "completed".to_string(),
            scan_id,
            progress: 100,
            stage: "completed".to_string(),
            details: None,
            timestamp: Utc::now(),
        }
    }

    /// Create a failure message
    pub fn failed(scan_id: String, error: String) -> Self {
        Self {
            msg_type: "failed".to_string(),
            scan_id,
            progress: 0,
            stage: "failed".to_string(),
            details: Some(error),
            timestamp: Utc::now(),
        }
    }
}
