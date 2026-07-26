// NNTP (Network News Transfer Protocol) STARTTLS Negotiator
// RFC 4642

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use super::text_protocol::{
    CapabilityCommand, CapabilityConfig, CapabilityResponseStyle, GreetingStyle, SuccessCheck,
    TextProtocolConfig,
};
use crate::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

const CONFIG: TextProtocolConfig = TextProtocolConfig {
    protocol_name: "NNTP",
    protocol: StarttlsProtocol::NNTP,
    greeting: GreetingStyle::StatusCodes(&[200, 201]),
    capability: Some(CapabilityConfig {
        command: CapabilityCommand::Static(b"CAPABILITIES\r\n"),
        starttls_marker: "STARTTLS",
        response_style: CapabilityResponseStyle::DotTerminated {
            first_line_prefix: None,
            first_line_status: Some(101),
        },
    }),
    starttls_command: b"STARTTLS\r\n",
    success: SuccessCheck::StatusCode(382),
};

/// NNTP STARTTLS negotiator
pub struct NntpNegotiator;

impl Default for NntpNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl NntpNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for NntpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        super::text_protocol::negotiate(&CONFIG, "", stream).await
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::NNTP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starttls::response;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
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

    async fn read_nntp_status(response: &'static [u8]) -> Result<(u16, String)> {
        let (addr, server) = spawn_response_server(response).await;
        let mut client = TcpStream::connect(addr)
            .await
            .expect("test client should connect");
        let mut reader = BufReader::new(&mut client);
        let result = response::read_status_line(&mut reader, "NNTP").await;

        server.await.expect("test server task should complete");
        result
    }

    async fn negotiate_with_nntp_server(
        greeting: &'static [u8],
        capabilities: Vec<&'static [u8]>,
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
                .write_all(greeting)
                .await
                .expect("test server should write response");

            let mut buffer = vec![0u8; 256];
            let _ = stream
                .read(&mut buffer)
                .await
                .expect("test should read data");

            for line in capabilities {
                stream
                    .write_all(line)
                    .await
                    .expect("test server should write response");
            }

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
        let result = NntpNegotiator::new().negotiate_starttls(&mut client).await;

        server.await.expect("test server task should complete");
        result
    }

    #[test]
    fn test_nntp_negotiator_creation() {
        let negotiator = NntpNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::NNTP);
    }

    #[tokio::test]
    async fn test_nntp_read_response_parse_error() {
        let err = read_nntp_status(b"abc\r\n").await.unwrap_err();
        assert!(format!("{err}").contains("Invalid NNTP status code"));
    }

    #[tokio::test]
    async fn test_nntp_read_response_valid() {
        let (code, line) = read_nntp_status(b"200 ready\r\n")
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 200);
        assert!(line.contains("ready"));
    }

    #[tokio::test]
    async fn test_nntp_negotiate_starttls_success() {
        let result = negotiate_with_nntp_server(
            b"200 server ready\r\n",
            vec![
                b"101 Capability list follows\r\n",
                b"VERSION 2\r\n",
                b"STARTTLS\r\n",
                b".\r\n",
            ],
            Some(b"382 Continue with TLS negotiation\r\n"),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nntp_negotiate_starttls_missing_starttls() {
        let result = negotiate_with_nntp_server(
            b"201 server ready\r\n",
            vec![
                b"101 Capability list follows\r\n",
                b"VERSION 2\r\n",
                b"MODE-READER\r\n",
                b".\r\n",
            ],
            None,
        )
        .await;
        assert!(result.is_err());
    }
}
