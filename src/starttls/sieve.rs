// Sieve (ManageSieve) STARTTLS Negotiator
// RFC 5804

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use super::text_protocol::{
    CapabilityCommand, CapabilityConfig, CapabilityResponseStyle, GreetingStyle, SuccessCheck,
    TextProtocolConfig,
};
use crate::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

const CONFIG: TextProtocolConfig = TextProtocolConfig {
    protocol_name: "Sieve",
    protocol: StarttlsProtocol::SIEVE,
    greeting: GreetingStyle::None,
    capability: Some(CapabilityConfig {
        command: CapabilityCommand::None,
        starttls_marker: "STARTTLS",
        response_style: CapabilityResponseStyle::UntilPrefix("OK"),
    }),
    starttls_command: b"STARTTLS\r\n",
    success: SuccessCheck::Prefix("OK"),
};

/// Sieve STARTTLS negotiator
pub struct SieveNegotiator;

impl Default for SieveNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl SieveNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for SieveNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        super::text_protocol::negotiate(&CONFIG, "", stream).await
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::SIEVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starttls::response;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_sieve_negotiator_creation() {
        let negotiator = SieveNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SIEVE);
    }

    #[test]
    fn test_sieve_negotiator_default() {
        let negotiator = SieveNegotiator;
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SIEVE);
    }

    async fn run_sieve_server(lines: &[&str], starttls_response: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let port = listener
            .local_addr()
            .expect("test listener should have local addr")
            .port();

        let lines = lines.iter().map(|l| l.to_string()).collect::<Vec<_>>();
        let starttls_response = starttls_response.to_string();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                for line in lines {
                    socket
                        .write_all(line.as_bytes())
                        .await
                        .expect("test assertion should succeed");
                }
                socket.flush().await.expect("test assertion should succeed");

                let mut reader = BufReader::new(&mut socket);
                let mut buf = String::new();
                let _ = reader.read_line(&mut buf).await;
                let _ = reader
                    .get_mut()
                    .write_all(starttls_response.as_bytes())
                    .await;
                let _ = reader.get_mut().flush().await;
            }
        });

        port
    }

    #[tokio::test]
    async fn test_sieve_negotiator_starttls_success() {
        let port = run_sieve_server(
            &[
                "IMPLEMENTATION \"test\"\r\n",
                "SASL \"PLAIN\"\r\n",
                "STARTTLS\r\n",
                "OK\r\n",
            ],
            "OK Begin TLS\r\n",
        )
        .await;

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let negotiator = SieveNegotiator::new();
        negotiator
            .negotiate_starttls(&mut stream)
            .await
            .expect("test assertion should succeed");
    }

    #[tokio::test]
    async fn test_sieve_negotiator_starttls_not_supported() {
        let port = run_sieve_server(&["IMPLEMENTATION \"test\"\r\n", "OK\r\n"], "OK\r\n").await;

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let negotiator = SieveNegotiator::new();
        assert!(negotiator.negotiate_starttls(&mut stream).await.is_err());
    }

    #[tokio::test]
    async fn test_sieve_negotiator_starttls_rejected() {
        let port = run_sieve_server(
            &["IMPLEMENTATION \"test\"\r\n", "STARTTLS\r\n", "OK\r\n"],
            "NO Not available\r\n",
        )
        .await;

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let negotiator = SieveNegotiator::new();
        assert!(negotiator.negotiate_starttls(&mut stream).await.is_err());
    }

    #[tokio::test]
    async fn test_sieve_read_response_line() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let port = listener
            .local_addr()
            .expect("test listener should have local addr")
            .port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"OK Ready\r\n").await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let mut reader = BufReader::new(&mut stream);
        let line = response::read_line(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert!(line.starts_with("OK"));
    }
}
