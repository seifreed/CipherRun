// Client CAs Phase - Extracts list of accepted client certificate authorities
//
// This phase extracts the list of Certificate Authorities (CAs) that the
// target server accepts for client certificate authentication. This is
// relevant for servers configured to request or require client certificates
// (mutual TLS / mTLS).
//
// Responsibilities (Single Responsibility Principle):
// - Configure client CA tester
// - Execute client CA enumeration
// - Store client CA list in scan context
//
// Dependencies:
// - ClientCAsTester (domain logic for CA list extraction)
// - ScanRequest (scan configuration)
// - Target (server information)
//
// Information extracted:
// - List of Distinguished Names (DNs) of accepted CAs
// - Number of accepted CAs
// - CA organizational information
// - Whether client certificates are requested vs. required

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use crate::protocols::client_cas::ClientCAsTester;
use async_trait::async_trait;

/// Client CAs enumeration phase
///
/// Extracts the list of Certificate Authorities that the target server
/// accepts for client certificate authentication. This information is
/// only available when the server requests or requires client certificates
/// during the TLS handshake.
///
/// Configuration sources (from ScanRequest):
/// - Client CA enumeration flag (--show-client-cas)
/// - Target information (hostname, port, resolved IPs)
pub struct ClientCasPhase;

impl ClientCasPhase {
    /// Create a new client CAs enumeration phase
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClientCasPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for ClientCasPhase {
    fn name(&self) -> &'static str {
        "Extracting Client CAs List"
    }

    fn should_run(&self, args: &ScanRequest) -> bool {
        // Run if:
        // - Explicit client CA enumeration requested (--show-client-cas)
        args.scan.ciphers.show_client_cas
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Create client CA tester with target
        let tester = ClientCAsTester::new(context.target())
            .with_sni(context.args.tls.sni_name.clone())
            .with_starttls(
                context.args.starttls_protocol(),
                context.args.starttls.xmpphost.clone(),
            )
            .with_starttls_server_mode(context.args.starttls_server_mode())
            .with_test_all_ips(context.args.network.test_all_ips);

        // Enumerate accepted client CAs
        // This extracts:
        // 1. List of CA Distinguished Names (DNs)
        // 2. Whether client certificates are required or optional
        // 3. CA organizational information
        let client_cas_results = tester.enumerate_client_cas().await?;

        // Store results in context (using new ISP-compliant structure)
        context.results.advanced_mut().client_cas = Some(client_cas_results);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::phases::test_scan_context;

    #[test]
    fn test_client_cas_phase_should_run() {
        let phase = ClientCasPhase::new();

        // Test with --show-client-cas flag
        let mut args = ScanRequest::default();
        args.scan.ciphers.show_client_cas = true;
        assert!(phase.should_run(&args));

        // Test without --show-client-cas flag
        let args = ScanRequest::default();
        assert!(!phase.should_run(&args));

        // Test with --all flag (should not enable client CA enumeration)
        let mut args = ScanRequest::default();
        args.scan.scope.all = true;
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_client_cas_phase_name() {
        let phase = ClientCasPhase::new();
        assert_eq!(phase.name(), "Extracting Client CAs List");
    }

    #[test]
    #[expect(clippy::default_constructed_unit_structs)]
    fn test_client_cas_phase_default() {
        let phase = ClientCasPhase::default();
        assert_eq!(phase.name(), "Extracting Client CAs List");
    }

    #[tokio::test]
    async fn test_execute_stores_client_ca_results() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("probe should connect");
            let mut request = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut request)
                .await
                .expect("read client hello");
        });

        let mut args = ScanRequest::default();
        args.scan.ciphers.show_client_cas = true;
        let mut context = test_scan_context(args);
        context.target = crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid loopback address")],
        )
        .expect("loopback target should build");

        ClientCasPhase::new()
            .execute(&mut context)
            .await
            .expect("closed TLS handshake should yield an inconclusive result");
        server.await.expect("server task should finish");

        assert!(
            context
                .results
                .advanced
                .as_ref()
                .and_then(|results| results.client_cas.as_ref())
                .is_some()
        );
    }
}
