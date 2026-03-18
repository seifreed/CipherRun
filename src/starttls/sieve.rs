// Sieve (ManageSieve) STARTTLS Negotiator
// RFC 5804

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

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

    async fn read_response(reader: &mut BufReader<&mut TcpStream>) -> Result<String> {
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        Ok(response)
    }
}

#[async_trait]
impl StarttlsNegotiator for SieveNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Read server capabilities (starts with "IMPLEMENTATION")
        let mut starttls_supported = false;
        loop {
            let response = Self::read_response(&mut reader).await?;

            if response.starts_with("OK") {
                break;
            }

            if response.to_uppercase().contains("STARTTLS") {
                starttls_supported = true;
            }
        }

        if !starttls_supported {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "Sieve".to_string(),
                details: "Server does not support STARTTLS".to_string(),
            });
        }

        // Send STARTTLS command
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read STARTTLS response (OK = ready to start TLS)
        let response = Self::read_response(&mut reader).await?;
        if !response.starts_with("OK") {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "Sieve".to_string(),
                details: format!("STARTTLS failed: {}", response),
            });
        }

        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::SIEVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn test_sieve_negotiator_creation() {
        let negotiator = SieveNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SIEVE);
    }

    #[test]
    fn test_sieve_negotiator_default() {
        let negotiator = SieveNegotiator::default();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SIEVE);
    }

    async fn run_sieve_server(lines: &[&str], starttls_response: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let port = listener.local_addr().unwrap().port();

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
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"OK Ready\r\n").await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let mut reader = BufReader::new(&mut stream);
        let line = SieveNegotiator::read_response(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert!(line.starts_with("OK"));
    }
}
