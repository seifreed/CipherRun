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

    #[test]
    fn test_nntp_negotiator_creation() {
        let negotiator = NntpNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::NNTP);
    }

    #[tokio::test]
    async fn test_nntp_read_response_parse_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("test listener should bind to localhost");
        let addr = listener.local_addr().expect("test listener should have local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test server should accept connection");
            stream.write_all(b"abc\r\n").await.expect("test server should write response");
        });

        let mut client = TcpStream::connect(addr).await.expect("test client should connect");
        let mut reader = BufReader::new(&mut client);
        let err = response::read_status_line(&mut reader, "NNTP")
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("Invalid NNTP status code"));

        server.await.expect("test server task should complete");
    }

    #[tokio::test]
    async fn test_nntp_read_response_valid() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("test listener should bind to localhost");
        let addr = listener.local_addr().expect("test listener should have local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test server should accept connection");
            stream.write_all(b"200 ready\r\n").await.expect("test server should write response");
        });

        let mut client = TcpStream::connect(addr).await.expect("test client should connect");
        let mut reader = BufReader::new(&mut client);
        let (code, line) = response::read_status_line(&mut reader, "NNTP")
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 200);
        assert!(line.contains("ready"));

        server.await.expect("test server task should complete");
    }

    #[tokio::test]
    async fn test_nntp_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("test listener should bind to localhost");
        let addr = listener.local_addr().expect("test listener should have local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test server should accept connection");
            stream.write_all(b"200 server ready\r\n").await.expect("test server should write response");

            let mut buffer = vec![0u8; 256];
            let _ = stream.read(&mut buffer).await.expect("test should read data");

            stream
                .write_all(b"101 Capability list follows\r\n")
                .await
                .expect("test server should write response");
            stream.write_all(b"VERSION 2\r\n").await.expect("test server should write response");
            stream.write_all(b"STARTTLS\r\n").await.expect("test server should write response");
            stream.write_all(b".\r\n").await.expect("test server should write response");

            let _ = stream.read(&mut buffer).await.expect("test should read data");
            stream
                .write_all(b"382 Continue with TLS negotiation\r\n")
                .await
                .expect("test server should write response");
        });

        let mut client = TcpStream::connect(addr).await.expect("test client should connect");
        let negotiator = NntpNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_ok());

        server.await.expect("test server task should complete");
    }

    #[tokio::test]
    async fn test_nntp_negotiate_starttls_missing_starttls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("test listener should bind to localhost");
        let addr = listener.local_addr().expect("test listener should have local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test server should accept connection");
            stream.write_all(b"201 server ready\r\n").await.expect("test server should write response");

            let mut buffer = vec![0u8; 256];
            let _ = stream.read(&mut buffer).await.expect("test should read data");

            stream
                .write_all(b"101 Capability list follows\r\n")
                .await
                .expect("test server should write response");
            stream.write_all(b"VERSION 2\r\n").await.expect("test server should write response");
            stream.write_all(b"MODE-READER\r\n").await.expect("test server should write response");
            stream.write_all(b".\r\n").await.expect("test server should write response");
        });

        let mut client = TcpStream::connect(addr).await.expect("test client should connect");
        let negotiator = NntpNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_err());

        server.await.expect("test server task should complete");
    }
}
