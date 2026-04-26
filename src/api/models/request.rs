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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<ScanOptions>,

    /// Optional webhook URL to call when scan completes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

/// Scan options
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct ScanOptions {
    /// Test all protocols (SSLv2, SSLv3, TLS 1.0-1.3)
    pub test_protocols: bool,

    /// Test all cipher suites
    pub test_ciphers: bool,

    /// Test all vulnerabilities
    pub test_vulnerabilities: bool,

    /// Analyze certificates
    pub analyze_certificates: bool,

    /// Test HTTP security headers
    pub test_http_headers: bool,

    /// Run client simulations
    pub client_simulation: bool,

    /// STARTTLS protocol (smtp, imap, pop3, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starttls_protocol: Option<String>,

    /// Connection and socket timeout in seconds
    pub timeout_seconds: u64,

    /// Use IPv4 only
    pub ipv4_only: bool,

    /// Use IPv6 only
    pub ipv6_only: bool,

    /// Specific IP address to test
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    /// Run full comprehensive scan
    pub full_scan: bool,
}

fn default_timeout() -> u64 {
    30
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            test_protocols: false,
            test_ciphers: false,
            test_vulnerabilities: false,
            analyze_certificates: false,
            test_http_headers: false,
            client_simulation: false,
            starttls_protocol: None,
            timeout_seconds: default_timeout(),
            ipv4_only: false,
            ipv6_only: false,
            ip: None,
            full_scan: false,
        }
    }
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

    /// Returns true when the API payload enables at least one real scan phase.
    pub fn has_requested_scan_work(&self) -> bool {
        self.test_protocols
            || self.test_ciphers
            || self.test_vulnerabilities
            || self.analyze_certificates
            || self.test_http_headers
            || self.client_simulation
            || self
                .starttls_protocol
                .as_deref()
                .is_some_and(|protocol| !protocol.trim().is_empty())
            || self.full_scan
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_options_defaults_via_serde() {
        let opts: ScanOptions = serde_json::from_str("{}").expect("test assertion should succeed");
        assert_eq!(opts.timeout_seconds, 30);
        assert!(!opts.test_protocols);
        assert!(!opts.test_ciphers);
    }

    #[test]
    fn test_scan_options_full_and_quick() {
        let full = ScanOptions::full();
        assert!(full.test_protocols);
        assert!(full.test_ciphers);
        assert!(full.test_vulnerabilities);
        assert!(full.analyze_certificates);
        assert!(full.test_http_headers);
        assert!(full.client_simulation);
        assert!(full.full_scan);

        let quick = ScanOptions::quick();
        assert!(quick.test_protocols);
        assert!(!quick.test_ciphers);
        assert!(!quick.test_vulnerabilities);
        assert!(quick.analyze_certificates);
        assert!(!quick.test_http_headers);
        assert!(!quick.client_simulation);
        assert!(!quick.full_scan);
    }

    #[test]
    fn test_scan_request_defaults_options_to_none() {
        let json = r#"{ "target": "example.com:443" }"#;
        let req: ScanRequest = serde_json::from_str(json).expect("test assertion should succeed");
        assert_eq!(req.target, "example.com:443");
        assert!(req.options.is_none());
        assert!(req.webhook_url.is_none());
    }

    #[test]
    fn test_scan_options_workload_detection() {
        assert!(!ScanOptions::default().has_requested_scan_work());
        assert!(ScanOptions::quick().has_requested_scan_work());
        assert!(
            ScanOptions {
                analyze_certificates: true,
                ..Default::default()
            }
            .has_requested_scan_work()
        );
        assert!(
            ScanOptions {
                starttls_protocol: Some("smtp".to_string()),
                ..Default::default()
            }
            .has_requested_scan_work()
        );
    }

    #[test]
    fn test_scan_options_blank_starttls_protocol_is_not_work() {
        let options = ScanOptions {
            starttls_protocol: Some(" \t ".to_string()),
            ..Default::default()
        };

        assert!(!options.has_requested_scan_work());
    }

    #[test]
    fn test_policy_request_default_enabled() {
        let json = r#"{ "name": "Policy", "rules": "rules" }"#;
        let req: PolicyRequest = serde_json::from_str(json).expect("test assertion should succeed");
        assert!(req.enabled);
    }

    #[test]
    fn test_certificate_query_default() {
        let query = CertificateQuery::default();
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 0);
        assert_eq!(query.sort, "expiry_asc");
        assert!(query.hostname.is_none());
        assert!(query.expiring_within_days.is_none());
    }

    #[test]
    fn test_certificate_query_defaults_from_serde() {
        let query: CertificateQuery =
            serde_json::from_str("{}").expect("test assertion should succeed");
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 0);
        assert_eq!(query.sort, "expiry_asc");
    }

    #[test]
    fn test_scan_options_default_ipv_flags() {
        let opts: ScanOptions = serde_json::from_str("{}").expect("test assertion should succeed");
        assert!(!opts.ipv4_only);
        assert!(!opts.ipv6_only);
    }
}
