// Protocol Tester - Tests which TLS/SSL protocols are supported

use super::{Protocol, ProtocolTestResult};
use crate::Result;
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Protocol testing configuration
pub struct ProtocolTester {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
    mtls_config: Option<MtlsConfig>,
    use_rdp: bool,
    enable_bugs_mode: bool,
    starttls_protocol: Option<crate::starttls::StarttlsProtocol>,
    sni_hostname: Option<String>,
    protocol_filter: Option<Vec<Protocol>>,
    test_all_ips: bool,
    retry_config: Option<crate::utils::retry::RetryConfig>,
}

impl ProtocolTester {
    /// Create new protocol tester
    pub fn new(target: Target) -> Self {
        // Auto-detect RDP based on port
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            mtls_config: None,
            use_rdp,
            enable_bugs_mode: false,
            starttls_protocol: None,
            sni_hostname: None,
            protocol_filter: None,
            test_all_ips: false,
            retry_config: None,
        }
    }

    /// Create new protocol tester with mTLS configuration
    pub fn with_mtls(target: Target, mtls_config: MtlsConfig) -> Self {
        // Auto-detect RDP based on port
        let use_rdp = crate::protocols::rdp::RdpPreamble::should_use_rdp(target.port);

        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            mtls_config: Some(mtls_config),
            use_rdp,
            enable_bugs_mode: false,
            starttls_protocol: None,
            sni_hostname: None,
            protocol_filter: None,
            test_all_ips: false,
            retry_config: None,
        }
    }

    /// Enable OpenSSL bug workarounds mode
    pub fn with_bugs_mode(mut self, enable: bool) -> Self {
        self.enable_bugs_mode = enable;
        self
    }

    /// Set STARTTLS protocol
    pub fn with_starttls(mut self, protocol: Option<crate::starttls::StarttlsProtocol>) -> Self {
        self.starttls_protocol = protocol;
        self
    }

    /// Set custom SNI hostname
    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    /// Set protocol filter
    pub fn with_protocol_filter(mut self, protocols: Option<Vec<Protocol>>) -> Self {
        self.protocol_filter = protocols;
        self
    }

    /// Set connect timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set read timeout
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Enable or disable RDP mode
    pub fn with_rdp(mut self, enable: bool) -> Self {
        self.use_rdp = enable;
        self
    }

    /// Enable testing all resolved IP addresses (for Anycast pools)
    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    /// Set retry configuration for handling transient network failures
    pub fn with_retry_config(mut self, config: Option<crate::utils::retry::RetryConfig>) -> Self {
        self.retry_config = config;
        self
    }

    /// Test all protocols
    pub async fn test_all_protocols(&self) -> Result<Vec<ProtocolTestResult>> {
        let mut results = Vec::new();

        // Determine which protocols to test
        let protocols_to_test = self.protocol_filter.clone().unwrap_or_else(Protocol::all);

        for protocol in protocols_to_test {
            let result = self.test_protocol(protocol).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Test specific protocol
    pub async fn test_protocol(&self, protocol: Protocol) -> Result<ProtocolTestResult> {
        let start = std::time::Instant::now();

        let supported = if self.test_all_ips {
            // Test all IPs and report minimum capability (like SSL Labs)
            // Protocol is supported ONLY if ALL IPs support it
            self.test_protocol_all_ips(protocol).await?
        } else {
            // Test only first IP (default behavior)
            let addr = self.target.socket_addrs()[0];
            self.test_protocol_on_ip(protocol, addr).await?
        };

        let handshake_time_ms = if supported {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        // Detect heartbeat extension support for supported protocols (TLS 1.0-1.3)
        let heartbeat_enabled = if supported && !matches!(protocol, Protocol::SSLv2 | Protocol::QUIC) {
            self.detect_heartbeat_extension(protocol).await.ok()
        } else {
            None
        };

        Ok(ProtocolTestResult {
            protocol,
            supported,
            preferred: false, // Will be determined later
            ciphers_count: 0, // Will be filled by cipher testing
            handshake_time_ms,
            heartbeat_enabled,
        })
    }

    /// Test protocol across all resolved IPs
    async fn test_protocol_all_ips(&self, protocol: Protocol) -> Result<bool> {
        let addrs = self.target.socket_addrs();

        if addrs.is_empty() {
            return Ok(false);
        }

        tracing::info!(
            "Testing {} IPs for hostname {} (protocol: {})",
            addrs.len(),
            self.target.hostname,
            protocol
        );

        let mut all_support = true;
        let mut any_tested = false;
        let mut per_ip_results = Vec::new();

        for (idx, addr) in addrs.iter().enumerate() {
            any_tested = true;
            let ip_supports = self.test_protocol_on_ip(protocol, *addr).await?;

            tracing::debug!(
                "IP {} ({}/{}): {} {} - {}",
                addr.ip(),
                idx + 1,
                addrs.len(),
                protocol,
                if ip_supports { "supported" } else { "NOT supported" },
                if ip_supports { "✓" } else { "✗" }
            );

            per_ip_results.push((addr.ip(), ip_supports));

            if !ip_supports {
                all_support = false;
            }
        }

        // Check for inconsistencies
        let inconsistent = per_ip_results.iter().any(|(_, s)| *s)
            && per_ip_results.iter().any(|(_, s)| !*s);

        if inconsistent {
            tracing::warn!(
                "WARNING: Inconsistent {} support across IPs for {}",
                protocol,
                self.target.hostname
            );
            for (ip, supported) in &per_ip_results {
                tracing::warn!(
                    "  {} {} - {}",
                    ip,
                    protocol,
                    if *supported { "SUPPORTED" } else { "NOT SUPPORTED" }
                );
            }
        }

        // Report minimum capability (like SSL Labs): supported only if ALL IPs support it
        Ok(any_tested && all_support)
    }

    /// Test protocol on specific IP address
    async fn test_protocol_on_ip(&self, protocol: Protocol, addr: std::net::SocketAddr) -> Result<bool> {
        match protocol {
            Protocol::SSLv2 => self.test_sslv2_on_ip(addr).await,
            Protocol::SSLv3 | Protocol::TLS10 | Protocol::TLS11 | Protocol::TLS12 => {
                self.test_tls_with_openssl_on_ip(protocol, addr).await
            }
            Protocol::TLS13 => self.test_tls13_on_ip(addr).await,
            Protocol::QUIC => self.test_quic_on_ip(addr).await,
        }
    }

    /// Test SSLv2 (custom implementation needed as it's not in modern libraries)
    async fn test_sslv2_on_ip(&self, addr: std::net::SocketAddr) -> Result<bool> {
        // SSLv2 uses a different handshake format
        // For now, we'll use a simple probe
        let stream_result = crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await;

        match stream_result {
            Ok(mut stream) => {
                // Send RDP preamble if needed
                if self.use_rdp
                    && crate::protocols::rdp::RdpPreamble::send(&mut stream)
                        .await
                        .is_err()
                {
                    return Ok(false);
                }

                // Perform STARTTLS negotiation if needed
                if let Some(starttls_proto) = self.starttls_protocol {
                    let negotiator = crate::starttls::protocols::get_negotiator(
                        starttls_proto,
                        self.target.hostname.clone(),
                    );
                    if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                        return Ok(false);
                    }
                }

                // Send SSLv2 ClientHello
                let client_hello = self.build_sslv2_client_hello();
                let mut response = vec![0u8; 1024];

                match timeout(self.read_timeout, async {
                    stream.write_all(&client_hello).await?;
                    stream.read(&mut response).await
                })
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if response looks like SSLv2 ServerHello
                        Ok(response[0] & 0x80 == 0x80)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Build SSLv2 ClientHello
    fn build_sslv2_client_hello(&self) -> Vec<u8> {
        let mut hello = vec![
            0x80, // Record header - high bit set
            0x00, // Length placeholder
            0x01, // Message type (CLIENT-HELLO)
            0x00, 0x02, // Version (SSLv2)
        ];

        // Cipher specs length
        hello.push(0x00);
        hello.push(0x06); // 3 ciphers * 3 bytes

        // Session ID length
        hello.push(0x00);
        hello.push(0x00);

        // Challenge length
        hello.push(0x00);
        hello.push(0x10); // 16 bytes

        // Cipher specs (3-byte each)
        hello.extend_from_slice(&[0x01, 0x00, 0x80]); // SSL_CK_RC4_128_WITH_MD5
        hello.extend_from_slice(&[0x02, 0x00, 0x80]); // SSL_CK_RC4_128_EXPORT40_WITH_MD5
        hello.extend_from_slice(&[0x03, 0x00, 0x80]); // SSL_CK_RC2_128_CBC_WITH_MD5

        // Challenge (16 random bytes)
        hello.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        hello.extend_from_slice(&[0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);

        // Fix length
        let len = hello.len() - 2;
        hello[1] = len as u8;

        hello
    }

    /// Test TLS protocols using OpenSSL
    async fn test_tls_with_openssl_on_ip(&self, protocol: Protocol, addr: std::net::SocketAddr) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        // Connect TCP with retry logic
        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(false);
            }
        }

        // Convert to std::net::TcpStream for OpenSSL
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        // Build SSL connector
        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Disable certificate verification for protocol testing
        use openssl::ssl::SslVerifyMode;
        builder.set_verify(SslVerifyMode::NONE);

        // Set specific protocol version
        let (min_version, max_version) = match protocol {
            Protocol::SSLv3 => (SslVersion::SSL3, SslVersion::SSL3),
            Protocol::TLS10 => (SslVersion::TLS1, SslVersion::TLS1),
            Protocol::TLS11 => (SslVersion::TLS1_1, SslVersion::TLS1_1),
            Protocol::TLS12 => (SslVersion::TLS1_2, SslVersion::TLS1_2),
            _ => return Ok(false),
        };

        builder.set_min_proto_version(Some(min_version))?;
        builder.set_max_proto_version(Some(max_version))?;

        // Enable bug workarounds if --bugs flag is set
        if self.enable_bugs_mode {
            use openssl::ssl::SslOptions;
            builder.set_options(SslOptions::ALL);
        }

        let connector = builder.build();

        // Get effective SNI hostname
        let sni_host = self.sni_hostname.as_ref().unwrap_or(&self.target.hostname);

        // Try to connect
        match connector.connect(sni_host, std_stream) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Test TLS 1.3 using rustls
    async fn test_tls13_on_ip(&self, addr: std::net::SocketAddr) -> Result<bool> {
        use rustls::{ClientConfig, RootCertStore};
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        // Connect TCP with retry logic
        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(false);
            }
        }

        // Build TLS connector with or without client auth
        let connector = if let Some(ref mtls_config) = self.mtls_config {
            // Use mTLS configuration
            match mtls_config.build_tls_connector() {
                Ok(c) => c,
                Err(_) => return Ok(false),
            }
        } else {
            // Build TLS config (TLS 1.3 only)
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            TlsConnector::from(Arc::new(config))
        };

        // Try to connect - use custom SNI if specified
        let sni_host = self.sni_hostname.as_ref().unwrap_or(&self.target.hostname);
        let domain = rustls_pki_types::ServerName::try_from(sni_host.as_str())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        match timeout(self.read_timeout, connector.connect(domain, stream)).await {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Test QUIC support (UDP-based protocol)
    ///
    /// QUIC testing is intentionally not implemented in this version because:
    /// 1. QUIC uses UDP instead of TCP, requiring different connection handling
    /// 2. Proper QUIC testing requires the quinn crate and additional dependencies
    /// 3. QUIC/HTTP3 adoption is still growing and many servers don't support it
    /// 4. The complexity-to-benefit ratio is currently not justified for a TLS scanner
    ///
    /// Future implementation would require:
    /// - quinn = "0.11" dependency
    /// - UDP socket handling
    /// - QUIC-specific handshake logic
    /// - Version negotiation support
    ///
    /// For now, this always returns false (QUIC not detected)
    async fn test_quic_on_ip(&self, _addr: std::net::SocketAddr) -> Result<bool> {
        // QUIC testing not implemented - requires UDP transport and quinn crate
        // This is a conscious design decision, not an incomplete implementation
        Ok(false)
    }

    /// Get preferred protocol (highest supported)
    pub async fn get_preferred_protocol(&self) -> Result<Option<Protocol>> {
        let results = self.test_all_protocols().await?;

        // Return highest supported protocol
        for protocol in [
            Protocol::TLS13,
            Protocol::TLS12,
            Protocol::TLS11,
            Protocol::TLS10,
            Protocol::SSLv3,
            Protocol::SSLv2,
        ] {
            if results
                .iter()
                .any(|r| r.protocol == protocol && r.supported)
            {
                return Ok(Some(protocol));
            }
        }

        Ok(None)
    }

    /// Detect heartbeat extension support for a specific protocol
    /// This performs a manual TLS handshake to check if ServerHello contains extension 0x000f
    async fn detect_heartbeat_extension(&self, protocol: Protocol) -> Result<bool> {
        use super::handshake::{ClientHelloBuilder, ServerHelloParser};

        let addr = self.target.socket_addrs()[0];

        // Connect TCP
        let mut stream = match timeout(
            self.read_timeout,
            crate::utils::network::connect_with_timeout(
                addr,
                self.connect_timeout,
                self.retry_config.as_ref(),
            ),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        // Send RDP preamble if needed
        if self.use_rdp
            && crate::protocols::rdp::RdpPreamble::send(&mut stream)
                .await
                .is_err()
        {
            return Ok(false);
        }

        // Perform STARTTLS negotiation if needed
        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.target.hostname.clone(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(false);
            }
        }

        // Build ClientHello with minimal ciphers
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(&[0xc030, 0xc02f, 0x009e, 0x0035]);

        // Use custom SNI if set, otherwise use target hostname
        let sni_hostname = self
            .sni_hostname
            .as_deref()
            .unwrap_or(&self.target.hostname);

        let client_hello = builder.build_with_defaults(Some(sni_hostname))?;

        // Send ClientHello and receive ServerHello
        let response = match timeout(self.read_timeout, async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(&client_hello).await?;

            // Read ServerHello (up to 16KB)
            let mut resp = vec![0u8; 16384];
            let n = stream.read(&mut resp).await?;
            resp.truncate(n);
            Ok::<Vec<u8>, anyhow::Error>(resp)
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => return Ok(false),
        };

        // Parse ServerHello to check for heartbeat extension
        match ServerHelloParser::parse(&response) {
            Ok(server_hello) => {
                // Check if heartbeat extension is present
                Ok(server_hello.supports_heartbeat().unwrap_or(false))
            }
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_protocol_detection() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = ProtocolTester::new(target);

        let results = tester.test_all_protocols().await.unwrap();

        // Google should support TLS 1.2 and 1.3
        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::TLS12 && r.supported)
        );
        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::TLS13 && r.supported)
        );

        // Should NOT support SSLv2 or SSLv3
        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::SSLv2 && !r.supported)
        );
        assert!(
            results
                .iter()
                .any(|r| r.protocol == Protocol::SSLv3 && !r.supported)
        );
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_preferred_protocol() {
        let target = Target::parse("www.google.com:443").await.unwrap();
        let tester = ProtocolTester::new(target);

        let preferred = tester.get_preferred_protocol().await.unwrap();

        // Should prefer TLS 1.3
        assert_eq!(preferred, Some(Protocol::TLS13));
    }

    #[test]
    fn test_sslv2_client_hello_build() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = ProtocolTester::new(target);
        let hello = tester.build_sslv2_client_hello();

        assert!(hello.len() > 30);
        assert_eq!(hello[0], 0x80); // High bit set
        assert_eq!(hello[2], 0x01); // CLIENT-HELLO
    }
}
