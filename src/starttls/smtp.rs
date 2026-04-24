// SMTP STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use super::text_protocol::{
    CapabilityCommand, CapabilityConfig, CapabilityResponseStyle, GreetingStyle, SuccessCheck,
    TextProtocolConfig,
};
use crate::Result;
use async_trait::async_trait;

const CONFIG: TextProtocolConfig = TextProtocolConfig {
    protocol_name: "SMTP",
    protocol: StarttlsProtocol::SMTP,
    greeting: GreetingStyle::StatusCode(220),
    capability: Some(CapabilityConfig {
        command: CapabilityCommand::WithHostname("EHLO {}\r\n"),
        starttls_marker: "STARTTLS",
        response_style: CapabilityResponseStyle::MultiLineStatus { code: 250 },
    }),
    starttls_command: b"STARTTLS\r\n",
    success: SuccessCheck::StatusCode(220),
};

/// SMTP STARTTLS negotiator
pub struct SmtpNegotiator {
    hostname: String,
}

impl SmtpNegotiator {
    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }
}

#[async_trait]
impl StarttlsNegotiator for SmtpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        super::text_protocol::negotiate(&CONFIG, &self.hostname, stream).await
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::SMTP
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("220")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starttls::response;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_smtp_negotiator_creation() {
        let negotiator = SmtpNegotiator::new("example.com".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SMTP);
        assert_eq!(negotiator.expected_greeting(), Some("220"));
    }

    #[tokio::test]
    async fn test_smtp_read_response_short_line() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let writer = tokio::spawn(async move {
            server
                .write_all(b"a\n")
                .await
                .expect("test server should write response");
        });

        let mut reader = BufReader::new(&mut client);
        let err = response::read_status_line(&mut reader, "SMTP")
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("too short"));

        writer.await.expect("test server task should complete");
    }

    #[tokio::test]
    async fn test_smtp_read_response_invalid_code() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let writer = tokio::spawn(async move {
            server
                .write_all(b"xx0 Invalid\r\n")
                .await
                .expect("test server should write response");
        });

        let mut reader = BufReader::new(&mut client);
        let err = response::read_status_line(&mut reader, "SMTP")
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("status code"));

        writer.await.expect("test server task should complete");
    }

    #[tokio::test]
    async fn test_smtp_read_response_valid_code() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let writer = tokio::spawn(async move {
            server
                .write_all(b"220 Ready\r\n")
                .await
                .expect("test server should write response");
        });

        let mut reader = BufReader::new(&mut client);
        let (code, line) = response::read_status_line(&mut reader, "SMTP")
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 220);
        assert!(line.contains("Ready"));

        writer.await.expect("test server task should complete");
    }

    #[tokio::test]
    async fn test_smtp_negotiate_starttls_success() {
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
                .write_all(b"250-localhost\r\n250-STARTTLS\r\n250 OK\r\n")
                .await
                .expect("test server should write response");

            let _ = stream
                .read(&mut buffer)
                .await
                .expect("test should read data");
            stream
                .write_all(b"220 Ready to start TLS\r\n")
                .await
                .expect("test server should write response");
        });

        let mut client = TcpStream::connect(addr)
            .await
            .expect("test client should connect");
        let negotiator = SmtpNegotiator::new("example.com".to_string());
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_ok());

        server.await.expect("test server task should complete");
    }

    #[tokio::test]
    async fn test_smtp_does_not_treat_nostarttls_as_starttls_capability() {
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
                .expect("test should read EHLO");

            stream
                .write_all(b"250-localhost\r\n250-NOSTARTTLS\r\n250 OK\r\n")
                .await
                .expect("test server should write capabilities");

            let _ = stream.read(&mut buffer).await;
        });

        let mut client = TcpStream::connect(addr)
            .await
            .expect("test client should connect");
        let negotiator = SmtpNegotiator::new("example.com".to_string());
        let err = negotiator
            .negotiate_starttls(&mut client)
            .await
            .expect_err("NOSTARTTLS must not enable STARTTLS");
        assert!(format!("{err}").contains("does not support STARTTLS"));
        drop(client);

        server.await.expect("test server task should complete");
    }
}
