// IMAP STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use super::text_protocol::{
    CapabilityCommand, CapabilityConfig, CapabilityResponseStyle, GreetingStyle, SuccessCheck,
    TextProtocolConfig,
};
use crate::Result;
use async_trait::async_trait;

const CONFIG: TextProtocolConfig = TextProtocolConfig {
    protocol_name: "IMAP",
    protocol: StarttlsProtocol::IMAP,
    greeting: GreetingStyle::Prefix("* OK"),
    capability: Some(CapabilityConfig {
        command: CapabilityCommand::Static(b"a001 CAPABILITY\r\n"),
        starttls_marker: "STARTTLS",
        response_style: CapabilityResponseStyle::UntilTagged {
            ok_prefix: "a001 OK",
            error_prefixes: &["a001 NO", "a001 BAD"],
        },
    }),
    starttls_command: b"a002 STARTTLS\r\n",
    success: SuccessCheck::Prefix("a002 OK"),
};

/// IMAP STARTTLS negotiator
pub struct ImapNegotiator;

impl ImapNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for ImapNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        super::text_protocol::negotiate(&CONFIG, "", stream).await
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::IMAP
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("* OK")
    }
}

impl Default for ImapNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starttls::response;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio::task::JoinHandle;

    async fn spawn_imap_server(send_starttls: bool) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut reader = BufReader::new(&mut socket);
                let _ = reader
                    .get_mut()
                    .write_all(b"* OK IMAP4rev1 Service Ready\r\n")
                    .await;
                let _ = reader.get_mut().flush().await;

                let mut buf = String::new();
                let _ = reader.read_line(&mut buf).await;

                if send_starttls {
                    let _ = reader
                        .get_mut()
                        .write_all(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n")
                        .await;
                    let _ = reader
                        .get_mut()
                        .write_all(b"a001 OK CAPABILITY completed\r\n")
                        .await;
                    let _ = reader.get_mut().flush().await;

                    buf.clear();
                    let _ = reader.read_line(&mut buf).await;

                    let _ = reader
                        .get_mut()
                        .write_all(b"a002 OK Begin TLS negotiation\r\n")
                        .await;
                    let _ = reader.get_mut().flush().await;
                } else {
                    let _ = reader
                        .get_mut()
                        .write_all(b"* CAPABILITY IMAP4rev1\r\n")
                        .await;
                    let _ = reader
                        .get_mut()
                        .write_all(b"a001 OK CAPABILITY completed\r\n")
                        .await;
                    let _ = reader.get_mut().flush().await;
                }
            }
        });

        (port, handle)
    }

    #[test]
    fn test_imap_negotiator_creation() {
        let negotiator = ImapNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::IMAP);
        assert_eq!(negotiator.expected_greeting(), Some("* OK"));
    }

    #[tokio::test]
    async fn test_imap_negotiation_success() {
        let (port, handle) = spawn_imap_server(true).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = ImapNegotiator::new();
        negotiator
            .negotiate_starttls(&mut stream)
            .await
            .expect("test assertion should succeed");

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_imap_negotiation_missing_starttls() {
        let (port, handle) = spawn_imap_server(false).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = ImapNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut stream).await;
        assert!(result.is_err());

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_imap_negotiation_bad_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"* BAD no greeting\r\n").await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = ImapNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut stream).await;
        assert!(result.is_err());

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_imap_read_response_line() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let _ = server.write_all(b"* OK Ready\r\n").await;
        });

        let mut reader = BufReader::new(&mut client);
        let line = response::read_line(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert!(line.starts_with("* OK"));
    }
}
