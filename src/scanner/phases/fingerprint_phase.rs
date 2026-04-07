// TLS Fingerprinting Phase - Captures and analyzes TLS fingerprints
//
// This phase is responsible for capturing various TLS fingerprints to
// identify client/server software, detect CDNs, and identify load balancers.
//
// Responsibilities (Single Responsibility Principle):
// - Capture JA3 client fingerprints (passive TLS client identification)
// - Capture JA3S server fingerprints (passive TLS server identification)
// - Generate JARM fingerprints (active TLS server fingerprinting)
// - Match fingerprints against signature databases
// - Detect CDNs and load balancers
// - Store fingerprint results in scan context
//
// Dependencies:
// - ClientHelloNetworkCapture (JA3 fingerprinting)
// - ServerHelloNetworkCapture (JA3S fingerprinting)
// - JarmFingerprinter (JARM active fingerprinting)
// - Ja3Database, Ja3sDatabase, JarmDatabase (signature matching)
// - ScanRequest (scan configuration for database paths, capture options)
//
// Fingerprinting methods:
// - JA3: Client TLS fingerprint (ClientHello parameters)
// - JA3S: Server TLS fingerprint (ServerHello parameters)
// - JARM: Active server fingerprint (multiple probe responses)
//
// Use cases:
// - Malware detection (known malicious JA3 signatures)
// - Bot detection (automated tool identification)
// - CDN identification (Cloudflare, Akamai, Fastly)
// - Load balancer detection (F5, HAProxy, nginx)
// - TLS stack identification (OpenSSL, BoringSSL, NSS)

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use async_trait::async_trait;

/// TLS fingerprinting phase
///
/// Captures TLS fingerprints for client identification, server profiling,
/// and infrastructure detection. Supports three fingerprinting methods:
/// - JA3 (passive client fingerprinting)
/// - JA3S (passive server fingerprinting)
/// - JARM (active server fingerprinting)
///
/// Configuration sources (from ScanRequest):
/// - JA3 capture (--ja3)
/// - JA3S capture (--ja3s)
/// - JARM capture (--jarm)
/// - Database paths (--ja3-database, --jarm-database)
/// - Raw capture (--client-hello, --server-hello)
pub struct FingerprintPhase;

impl FingerprintPhase {
    /// Create a new TLS fingerprinting phase
    pub fn new() -> Self {
        Self
    }

    /// Capture JA3 client fingerprint
    ///
    /// JA3 is a method for creating SSL/TLS client fingerprints that are
    /// easy to produce and can be used for identifying malware, bots, and
    /// other automated tools.
    ///
    /// The fingerprint is an MD5 hash of specific TLS ClientHello parameters:
    /// - TLS version
    /// - Accepted ciphers
    /// - List of extensions
    /// - Elliptic curves
    /// - Elliptic curve point formats
    async fn capture_ja3(&self, context: &mut ScanContext) -> Result<()> {
        use crate::fingerprint::{ClientHelloNetworkCapture, Ja3Database};

        let target = context.target();

        // Capture ClientHello and generate JA3 fingerprint
        let capture = ClientHelloNetworkCapture::new(target);
        let (client_hello, ja3) = capture.capture_and_fingerprint().await?;

        // Store JA3 fingerprint in the fingerprints sub-struct
        let fingerprints = context.results.fingerprints_mut();
        fingerprints.ja3_fingerprint = Some(ja3.clone());

        // Match against signature database
        let db = if let Some(ref db_path) = context.args.fingerprint.ja3_database {
            Ja3Database::from_file(db_path).unwrap_or_default()
        } else {
            Ja3Database::default()
        };

        if let Some(signature) = db.match_fingerprint(&ja3.ja3_hash) {
            fingerprints.ja3_match = Some(signature.clone());
        }

        // Store raw ClientHello if requested
        if context.args.fingerprint.client_hello {
            fingerprints.client_hello_raw = Some(client_hello.to_bytes());
        }

        Ok(())
    }

    /// Capture JA3S server fingerprint
    ///
    /// JA3S is the server-side version of JA3. It fingerprints the TLS
    /// ServerHello message to identify the server's TLS stack.
    ///
    /// The fingerprint is an MD5 hash of specific TLS ServerHello parameters:
    /// - TLS version
    /// - Accepted cipher
    /// - List of extensions
    ///
    /// JA3S can identify:
    /// - TLS implementation (OpenSSL, BoringSSL, NSS, SChannel)
    /// - CDN providers (Cloudflare, Akamai, Fastly)
    /// - Load balancers (F5, HAProxy, nginx)
    async fn capture_ja3s(&self, context: &mut ScanContext) -> Result<()> {
        use crate::fingerprint::{Ja3sDatabase, Ja3sFingerprint, ServerHelloNetworkCapture};

        let target = context.target();

        // Capture ServerHello and generate JA3S fingerprint
        let capturer = ServerHelloNetworkCapture::new(target);
        let server_hello = capturer.capture()?;
        let server_hello_raw = server_hello.to_bytes();
        let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

        // Match against signature database
        let ja3s_db = match Ja3sDatabase::load_default() {
            Ok(db) => db,
            Err(e) => {
                eprintln!("Warning: Failed to load JA3S database: {}", e);
                eprintln!("Continuing without JA3S signature matching");
                Ja3sDatabase::empty()
            }
        };

        let ja3s_match = ja3s_db.match_fingerprint(&ja3s.ja3s_hash).cloned();

        // CDN detection (requires HTTP headers from previous phase)
        // Extract headers first to avoid borrow issues
        let header_map: Option<std::collections::HashMap<String, String>> = context
            .results
            .http
            .as_ref()
            .and_then(|http| http.http_headers.as_ref())
            .map(|http_headers| {
                http_headers
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            });

        if let Some(header_map) = header_map {
            let advanced = context.results.advanced_mut();
            advanced.cdn_detection = Some(crate::fingerprint::CdnDetection::from_ja3s_and_headers(
                &ja3s,
                ja3s_match.as_ref(),
                &header_map,
            ));

            advanced.load_balancer_info =
                Some(crate::fingerprint::LoadBalancerInfo::from_ja3s_and_headers(
                    ja3s_match.as_ref(),
                    &header_map,
                ));
        }

        // Store JA3S fingerprint in the fingerprints sub-struct
        let fingerprints = context.results.fingerprints_mut();
        fingerprints.ja3s_fingerprint = Some(ja3s);
        fingerprints.ja3s_match = ja3s_match;

        // Store raw ServerHello if requested
        if context.args.fingerprint.server_hello {
            fingerprints.server_hello_raw = Some(server_hello_raw);
        }

        Ok(())
    }

    /// Generate JARM server fingerprint
    ///
    /// JARM is an active TLS server fingerprinting tool. It sends 10 different
    /// TLS ClientHello packets to a server and analyzes the responses to create
    /// a unique fingerprint.
    ///
    /// JARM is more robust than JA3S because:
    /// - It uses multiple probes (10 different ClientHellos)
    /// - It detects TLS implementation variations
    /// - It's harder to evade than passive fingerprinting
    ///
    /// JARM fingerprints can identify:
    /// - Specific server applications (Apache, nginx, IIS)
    /// - Cloud providers (AWS, Google Cloud, Azure)
    /// - Security appliances (WAF, IPS)
    /// - Malicious infrastructure (C2 servers, phishing sites)
    async fn capture_jarm(&self, context: &mut ScanContext) -> Result<()> {
        use crate::fingerprint::{JarmDatabase, JarmFingerprinter};
        use std::time::Duration;

        // Load custom database if specified, otherwise use builtin
        let database = if let Some(ref db_path) = context.args.fingerprint.jarm_database {
            JarmDatabase::from_file(db_path.to_str().ok_or_else(|| {
                crate::error::TlsError::ConfigError {
                    message: "Invalid JARM database path".into(),
                }
            })?)
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to load custom JARM database: {}", e);
                eprintln!("Falling back to builtin database");
                JarmDatabase::builtin()
            })
        } else {
            JarmDatabase::builtin()
        };

        // Use socket timeout if specified, otherwise default to 5 seconds
        let timeout = Duration::from_secs(context.args.connection.socket_timeout.unwrap_or(5));

        let fingerprinter = JarmFingerprinter::with_database(timeout, database);

        // Get first IP address for JARM fingerprinting
        let ip = context.target.ip_addresses.first().ok_or_else(|| {
            crate::error::TlsError::Other("No IP address resolved for target".into())
        })?;

        let addr = std::net::SocketAddr::new(*ip, context.target.port);
        let hostname = context.target.hostname.clone();

        // Generate JARM fingerprint
        let jarm = fingerprinter.fingerprint(addr, &hostname).await?;

        // Store JARM fingerprint in the fingerprints sub-struct
        context.results.fingerprints_mut().jarm_fingerprint = Some(jarm);

        Ok(())
    }
}

impl Default for FingerprintPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for FingerprintPhase {
    fn name(&self) -> &'static str {
        "Capturing TLS Fingerprints"
    }

    fn should_run(&self, args: &ScanRequest) -> bool {
        args.should_run_fingerprint_phase()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Capture JA3 if requested
        if context.args.should_run_ja3_fingerprint()
            && let Err(e) = self.capture_ja3(context).await
        {
            eprintln!("  Failed to generate JA3 fingerprint: {}", e);
        }

        // Capture JA3S if requested
        if context.args.should_run_ja3s_fingerprint()
            && let Err(e) = self.capture_ja3s(context).await
        {
            eprintln!("  Failed to generate JA3S fingerprint: {}", e);
        }

        // Capture JARM if requested
        if context.args.should_run_jarm_fingerprint()
            && let Err(e) = self.capture_jarm(context).await
        {
            eprintln!("  Failed to generate JARM fingerprint: {}", e);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_fingerprint_phase_should_run() {
        let phase = FingerprintPhase::new();

        // Test with --ja3 flag (explicit)
        let mut args = ScanRequest::default();
        args.scan.all = false;
        args.fingerprint.explicit_ja3 = true;
        assert!(phase.should_run(&args));

        // Test with --ja3s flag (explicit)
        let mut args = ScanRequest::default();
        args.scan.all = false;
        args.fingerprint.explicit_ja3s = true;
        assert!(phase.should_run(&args));

        // Test with --jarm flag (explicit)
        let mut args = ScanRequest::default();
        args.scan.all = false;
        args.fingerprint.explicit_jarm = true;
        assert!(phase.should_run(&args));

        // Default args do not imply baseline on their own.
        let args = ScanRequest::default();
        assert!(
            !phase.should_run(&args),
            "Default config should not run without baseline"
        );

        // Baseline enables implicit default fingerprints.
        let mut args = ScanRequest::default();
        args.scan.all = true;
        assert!(
            phase.should_run(&args),
            "Baseline should enable default fingerprints"
        );

        // Test with all fingerprint flags explicitly disabled
        let mut args = ScanRequest::default();
        args.scan.all = true;
        args.fingerprint.ja3 = false;
        args.fingerprint.ja3s = false;
        args.fingerprint.jarm = false;
        assert!(
            !phase.should_run(&args),
            "Should not run when all fingerprint flags disabled"
        );

        // Test with --all=false and no explicit fingerprint request
        let mut args = ScanRequest::default();
        args.scan.all = false;
        assert!(
            !phase.should_run(&args),
            "Should not run with --all=false and implicit defaults only"
        );
    }

    #[test]
    fn test_fingerprint_phase_name() {
        let phase = FingerprintPhase::new();
        assert_eq!(phase.name(), "Capturing TLS Fingerprints");
    }

    #[test]
    fn test_fingerprint_phase_should_run_multiple_flags() {
        let phase = FingerprintPhase::new();
        let mut args = ScanRequest::default();
        args.scan.all = false;
        args.fingerprint.explicit_ja3 = true;
        args.fingerprint.explicit_jarm = true;
        assert!(phase.should_run(&args));
    }

    #[test]
    fn test_fingerprint_phase_default_trait() {
        let phase: FingerprintPhase = Default::default();
        assert_eq!(phase.name(), "Capturing TLS Fingerprints");
    }

    #[tokio::test]
    async fn test_execute_no_flags_no_fingerprints() {
        // This test verifies that when no fingerprint flags are set,
        // the execute method doesn't modify the results
        let target = crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            443,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");

        let mut args = ScanRequest::default();
        // Explicitly ensure all fingerprint flags are false
        args.fingerprint.ja3 = false;
        args.fingerprint.ja3s = false;
        args.fingerprint.jarm = false;

        let args = Arc::new(args);
        let mut context = ScanContext::new(target, args, None, None);

        // Before execute, fingerprints should be None
        assert!(context.results.fingerprints.is_none());

        let phase = FingerprintPhase::new();

        // Execute should run without error since no fingerprint flags are set
        // and should_run returns false
        let result = phase.execute(&mut context).await;

        // The execute should complete successfully (no fingerprint methods called)
        // Even if connection fails, execute should return Ok since errors are caught internally
        // But since should_run is false, it should do nothing
        assert!(result.is_ok(), "execute should return Ok with no flags");

        // After execute, fingerprints should still be None
        // (we didn't set any fingerprint flags)
        assert!(
            context.results.fingerprints.is_none(),
            "fingerprints should remain None when no flags are set"
        );
    }
}
