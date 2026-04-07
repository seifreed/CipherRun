// HTTP Security Headers Analysis Phase - Analyzes HTTP security headers
//
// This phase is responsible for analyzing HTTP security headers returned
// by the target server and evaluating their security posture.
//
// Responsibilities (Single Responsibility Principle):
// - Configure HTTP header analyzer with CLI arguments
// - Fetch and analyze HTTP response headers
// - Evaluate security headers (HSTS, CSP, X-Frame-Options, etc.)
// - Store header analysis results in scan context
//
// Dependencies:
// - HeaderAnalyzer (domain logic for HTTP header analysis)
// - ScanRequest (scan configuration for custom headers, user agent)
// - Target (server information)
//
// Security headers analyzed:
// - HSTS (HTTP Strict Transport Security)
// - CSP (Content Security Policy)
// - X-Frame-Options (clickjacking protection)
// - X-Content-Type-Options (MIME sniffing protection)
// - X-XSS-Protection (XSS filter)
// - Referrer-Policy (referrer information control)
// - Permissions-Policy (feature policy)
// - Set-Cookie flags (Secure, HttpOnly, SameSite)

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use crate::http::tester::HeaderAnalyzer;
use async_trait::async_trait;

/// HTTP security headers analysis phase
///
/// Analyzes HTTP security headers to identify missing or misconfigured
/// security controls. This phase makes an HTTPS request to the target
/// and evaluates the response headers.
///
/// Configuration sources (from ScanRequest):
/// - Custom headers (--header "Name: Value")
/// - User agent override (--sneaky mode)
/// - Header testing enable/disable (--headers)
/// - Baseline scan policy for implicit execution
pub struct HttpHeadersPhase;

impl HttpHeadersPhase {
    /// Create a new HTTP headers analysis phase
    pub fn new() -> Self {
        Self
    }

    /// Configure HeaderAnalyzer with CLI arguments
    ///
    /// This method implements the Builder Pattern to construct a properly
    /// configured HeaderAnalyzer based on CLI flags. It applies:
    /// 1. Custom headers from --header flags
    /// 2. User agent override for sneaky mode
    ///
    /// Custom headers format: "Header-Name: Header-Value"
    /// Example: --header "Authorization: Bearer token123"
    fn configure_analyzer(&self, context: &ScanContext) -> HeaderAnalyzer {
        let target = context.target();

        // Create base analyzer
        let mut analyzer = if !context.args.http.custom_headers.is_empty() {
            // Parse custom headers from CLI format "Header: Value"
            let custom_headers: Vec<(String, String)> = context
                .args
                .http
                .custom_headers
                .iter()
                .filter_map(|h| {
                    // Split on first colon only
                    let parts: Vec<&str> = h.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
                    } else {
                        eprintln!(
                            "Warning: Invalid header format '{}', expected 'Name: Value'",
                            h
                        );
                        None
                    }
                })
                .collect();

            HeaderAnalyzer::with_custom_headers(target, custom_headers)
        } else {
            HeaderAnalyzer::new(target)
        };

        // Apply sneaky mode user agent if enabled
        // Sneaky mode uses a common browser user agent to avoid detection
        if context.args.http.sneaky {
            use crate::utils::sneaky::SneakyConfig;
            let sneaky_config = SneakyConfig::new(true);
            analyzer = analyzer.with_user_agent(sneaky_config.user_agent().to_string());
        }

        analyzer
    }
}

impl Default for HttpHeadersPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for HttpHeadersPhase {
    fn name(&self) -> &'static str {
        "Analyzing HTTP Security Headers"
    }

    fn should_run(&self, args: &ScanRequest) -> bool {
        // Run if:
        // - Explicit header analysis requested (--headers)
        // - Baseline scan policy enables implicit header analysis
        args.should_run_http_headers_phase()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Configure analyzer with all CLI options
        let analyzer = self.configure_analyzer(context);

        // Fetch and analyze HTTP headers
        // The analyze() method:
        // 1. Establishes HTTPS connection to target
        // 2. Sends HTTP GET request with custom headers
        // 3. Parses response headers
        // 4. Evaluates security headers against best practices
        // 5. Assigns a security grade (A, B, C, D, F)
        let header_results = analyzer.analyze().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.http_mut().http_headers = Some(header_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn build_context(args: ScanRequest) -> ScanContext {
        let target = crate::utils::network::Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .expect("test assertion should succeed");
        ScanContext::new(target, Arc::new(args), None, None)
    }

    #[test]
    fn test_http_headers_phase_should_run() {
        let phase = HttpHeadersPhase::new();

        // Test with --headers flag
        let mut args = ScanRequest::default();
        args.scan.headers = true;
        assert!(phase.should_run(&args));

        // Test with --all flag
        let mut args = ScanRequest::default();
        args.scan.all = true;
        assert!(phase.should_run(&args));

        // Specific-focus scans should not implicitly enable header analysis.
        let mut args = ScanRequest::default();
        args.scan.all = true;
        args.scan.show_sigs = true;
        assert!(!phase.should_run(&args));

        // Test with target specified (default scan, should NOT run)
        let args = ScanRequest {
            target: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(!phase.should_run(&args));

        // Test with no relevant flags
        let args = ScanRequest::default();
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_http_headers_phase_name() {
        let phase = HttpHeadersPhase::new();
        assert_eq!(phase.name(), "Analyzing HTTP Security Headers");
    }

    #[test]
    fn test_http_headers_phase_configure_analyzer_custom_headers() {
        let mut args = ScanRequest::default();
        args.http.custom_headers = vec!["X-Test: value".to_string(), "BrokenHeader".to_string()];
        let context = build_context(args);
        let phase = HttpHeadersPhase::new();
        let _analyzer = phase.configure_analyzer(&context);
    }

    #[test]
    fn test_http_headers_phase_configure_analyzer_sneaky() {
        let mut args = ScanRequest::default();
        args.http.sneaky = true;
        let context = build_context(args);
        let phase = HttpHeadersPhase::new();
        let _analyzer = phase.configure_analyzer(&context);
    }
}
