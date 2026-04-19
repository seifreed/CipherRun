use super::IntoleranceTester;
use crate::Result;
use crate::constants::{ALERT_LEVEL_FATAL, BUFFER_SIZE_MAX_TLS_RECORD, CONTENT_TYPE_ALERT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

impl IntoleranceTester {
    pub(super) async fn send_client_hello(&self, client_hello: &[u8]) -> Result<Vec<u8>> {
        use crate::TlsError;

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None).await?;

        let (mut reader, mut writer) = tokio::io::split(stream);
        writer.write_all(client_hello).await?;
        writer.flush().await?;

        let mut response = vec![0u8; BUFFER_SIZE_MAX_TLS_RECORD];
        match timeout(self.read_timeout, reader.read(&mut response)).await {
            Ok(Ok(n)) if n > 0 => {
                response.truncate(n);
                Ok(response)
            }
            _ => Err(TlsError::Timeout {
                duration: self.read_timeout,
            }),
        }
    }

    pub(super) async fn send_and_read_alert(&self, client_hello: &[u8]) -> Result<Option<u8>> {
        match self.send_client_hello(client_hello).await {
            Ok(response) => {
                if response.len() >= 7
                    && response[0] == CONTENT_TYPE_ALERT
                    && response[5] == ALERT_LEVEL_FATAL
                {
                    Ok(Some(response[6]))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                // Log network errors for debugging - these may indicate connectivity issues
                // or server-side problems, but should not fail the test
                tracing::debug!(
                    "Failed to send client_hello for intolerance test ({}): {}",
                    self.target.hostname,
                    e
                );
                Ok(None)
            }
        }
    }

    pub(super) async fn extract_dh_prime(&self) -> Result<Option<String>> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None).await?;

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cipher_list("DHE:EDH:!aNULL:!eNULL")?;

        let connector = builder.build();
        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                let cipher = ssl_stream.ssl().current_cipher();
                if let Some(c) = cipher
                    && c.name().contains("DHE")
                {
                    // Extract the DH prime from the negotiated connection
                    if let Ok(tmp_key) = ssl_stream.ssl().tmp_key()
                        && let Ok(dh) = tmp_key.dh()
                        && let Ok(hex_str) = dh.prime_p().to_hex_str()
                    {
                        return Ok(Some(hex_str.to_string().to_uppercase()));
                    }
                    return Ok(None);
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    pub(super) fn load_common_primes() -> Result<Vec<String>> {
        let primes_data = include_str!("../../../data/common-primes.txt");
        let mut primes = Vec::new();

        for line in primes_data.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            primes.push(trimmed.to_uppercase());
        }

        Ok(primes)
    }
}
