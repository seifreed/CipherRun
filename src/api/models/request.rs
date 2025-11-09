// API Request Models

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Scan request payload
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanRequest {
    /// Target to scan (hostname:port or just hostname)
    #[schema(example = "example.com:443")]
    pub target: String,

    /// Optional scan options
    #[serde(default)]
    pub options: ScanOptions,

    /// Optional webhook URL to call when scan completes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

/// Scan options
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ScanOptions {
    /// Test all protocols (SSLv2, SSLv3, TLS 1.0-1.3)
    #[serde(default)]
    pub test_protocols: bool,

    /// Test all cipher suites
    #[serde(default)]
    pub test_ciphers: bool,

    /// Test all vulnerabilities
    #[serde(default)]
    pub test_vulnerabilities: bool,

    /// Analyze certificates
    #[serde(default)]
    pub analyze_certificates: bool,

    /// Test HTTP security headers
    #[serde(default)]
    pub test_http_headers: bool,

    /// Run client simulations
    #[serde(default)]
    pub client_simulation: bool,

    /// STARTTLS protocol (smtp, imap, pop3, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starttls_protocol: Option<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Use IPv4 only
    #[serde(default)]
    pub ipv4_only: bool,

    /// Use IPv6 only
    #[serde(default)]
    pub ipv6_only: bool,

    /// Specific IP address to test
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    /// Run full comprehensive scan
    #[serde(default)]
    pub full_scan: bool,
}

fn default_timeout() -> u64 {
    30
}

impl ScanOptions {
    /// Create options for a full scan
    pub fn full() -> Self {
        Self {
            test_protocols: true,
            test_ciphers: true,
            test_vulnerabilities: true,
            analyze_certificates: true,
            test_http_headers: true,
            client_simulation: true,
            full_scan: true,
            ..Default::default()
        }
    }

    /// Create options for a quick scan
    pub fn quick() -> Self {
        Self {
            test_protocols: true,
            test_ciphers: false,
            test_vulnerabilities: false,
            analyze_certificates: true,
            test_http_headers: false,
            client_simulation: false,
            ..Default::default()
        }
    }
}

/// Policy creation/update request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyRequest {
    /// Policy name
    pub name: String,

    /// Policy description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Policy rules in YAML format
    pub rules: String,

    /// Policy enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Policy evaluation request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyEvaluationRequest {
    /// Target to evaluate
    pub target: String,

    /// Scan options
    #[serde(default)]
    pub options: ScanOptions,
}

/// Certificate query parameters
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, IntoParams)]
pub struct CertificateQuery {
    /// Maximum number of results
    #[serde(default = "default_limit")]
    pub limit: usize,

    /// Offset for pagination
    #[serde(default)]
    pub offset: usize,

    /// Sort order (expiry_asc, expiry_desc, issued_asc, issued_desc)
    #[serde(default = "default_sort")]
    pub sort: String,

    /// Filter by hostname
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Filter by expiring within days
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiring_within_days: Option<u32>,
}

fn default_limit() -> usize {
    50
}

fn default_sort() -> String {
    "expiry_asc".to_string()
}

impl Default for CertificateQuery {
    fn default() -> Self {
        Self {
            limit: default_limit(),
            offset: 0,
            sort: default_sort(),
            hostname: None,
            expiring_within_days: None,
        }
    }
}

/// Compliance check parameters
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ComplianceCheckRequest {
    /// Target to check
    pub target: String,

    /// Framework (pci-dss-v4, nist-sp800-52r2, etc.)
    pub framework: String,

    /// Generate detailed report
    #[serde(default)]
    pub detailed: bool,
}
