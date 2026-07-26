// LMTP (Local Mail Transfer Protocol) STARTTLS Negotiator
// RFC 2033

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use super::text_protocol::{
    CapabilityCommand, CapabilityConfig, CapabilityResponseStyle, GreetingStyle, SuccessCheck,
    TextProtocolConfig,
};
use crate::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

const CONFIG: TextProtocolConfig = TextProtocolConfig {
    protocol_name: "LMTP",
    protocol: StarttlsProtocol::LMTP,
    // RFC 2033/5321 permit a multiline 220 greeting; a single-line read would
    // leave continuation lines buffered and misparse them as the LHLO response,
    // falsely reporting STARTTLS absent.
    greeting: GreetingStyle::MultilineStatus(220),
    capability: Some(CapabilityConfig {
        command: CapabilityCommand::WithHostname("LHLO {}\r\n"),
        starttls_marker: "STARTTLS",
        response_style: CapabilityResponseStyle::MultiLineStatus { code: 250 },
    }),
    starttls_command: b"STARTTLS\r\n",
    success: SuccessCheck::StatusCode(220),
};

/// LMTP STARTTLS negotiator (similar to SMTP)
pub struct LmtpNegotiator {
    hostname: String,
}

impl LmtpNegotiator {
    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }
}

#[async_trait]
impl StarttlsNegotiator for LmtpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        super::text_protocol::negotiate(&CONFIG, &self.hostname, stream).await
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::LMTP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starttls::response;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    async fn spawn_response_server(
        response: &'static [u8],
    ) -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind to localhost");
        let addr = listener
            .local_addr()
            .expect("test listener should have local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test server should accept connection");
            stream
                .write_all(response)
                .await
                .expect("test server should write response");
        });

        (addr, server)
    }

    async fn read_lmtp_status(response: &'static [u8]) -> Result<(u16, String)> {
        let (addr, server) = spawn_response_server(response).await;
        let mut client = TcpStream::connect(addr)
            .await
            .expect("test client should connect");
        let mut reader = BufReader::new(&mut client);
        let result = response::read_status_line(&mut reader, "LMTP").await;

        server.await.expect("test server task should complete");
        result
    }

    async fn negotiate_with_lmtp_server(
        capability_response: &'static [u8],
        starttls_response: Option<&'static [u8]>,
    ) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind to localhost");
        let addr = listener
            .local_addr()
            .expect("test listener should have local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test server should accept connection");
            stream
                .write_all(b"220 ready\r\n")
                .await
                .expect("test server should write response");

            let mut buffer = vec![0u8; 256];
            let _ = stream
                .read(&mut buffer)
                .await
                .expect("test should read data");
            stream
                .write_all(capability_response)
                .await
                .expect("test server should write response");

            if let Some(response) = starttls_response {
                let _ = stream
                    .read(&mut buffer)
                    .await
                    .expect("test should read data");
                stream
                    .write_all(response)
                    .await
                    .expect("test server should write response");
            }
        });

        let mut client = TcpStream::connect(addr)
            .await
            .expect("test client should connect");
        let result = LmtpNegotiator::new("localhost".to_string())
            .negotiate_starttls(&mut client)
            .await;

        server.await.expect("test server task should complete");
        result
    }

    #[test]
    fn test_lmtp_negotiator_creation() {
        let negotiator = LmtpNegotiator::new("localhost".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::LMTP);
    }

    #[tokio::test]
    async fn test_lmtp_read_response_invalid() {
        let err = read_lmtp_status(b"\r\n").await.unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    #[tokio::test]
    async fn test_lmtp_read_response_valid() {
        let (code, line) = read_lmtp_status(b"250 OK\r\n")
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 250);
        assert!(line.contains("OK"));
    }

    #[tokio::test]
    async fn test_lmtp_negotiate_starttls_success() {
        negotiate_with_lmtp_server(b"250-STARTTLS\r\n250 OK\r\n", Some(b"220 go ahead\r\n"))
            .await
            .expect("test LMTP negotiation should succeed");
    }

    #[tokio::test]
    async fn test_lmtp_negotiate_starttls_rejects_starttls() {
        let err = negotiate_with_lmtp_server(b"250 OK\r\n", None)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("does not support STARTTLS"));
    }

    #[tokio::test]
    async fn test_lmtp_negotiate_starttls_lhlo_failed() {
        let err = negotiate_with_lmtp_server(b"500 LHLO failed\r\n", None)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("capability failed"));
    }
}
