// Network probing for POODLE vulnerability detection
//
// Handles TLS connection establishment, sending malformed records,
// and capturing server responses for oracle analysis.

use crate::Result;
use crate::constants::{CONTENT_TYPE_ALERT, TLS_HANDSHAKE_TIMEOUT};
use crate::utils::network::Target;
use crate::utils::{VulnSslConfig, test_vuln_ssl_connection};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use super::record_builder;
use super::{MalformedRecordType, ServerResponse};

/// Check if server supports CBC cipher suites
pub(super) async fn supports_cbc_ciphers(target: &Target) -> Result<bool> {
    const CBC_CIPHERS: &str = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA";
    test_vuln_ssl_connection(target, VulnSslConfig::with_ciphers(CBC_CIPHERS))
        .await
        .map_err(crate::TlsError::from)
}

/// Send a malformed TLS record for oracle detection
pub(super) async fn send_malformed_record(
    target: &Target,
    record_type: MalformedRecordType,
) -> Result<ServerResponse> {
    let addr = target
        .socket_addrs()
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No socket addresses available for target"))?;
    let start_time = Instant::now();

    match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None).await {
        Ok(mut stream) => {
            // Send ClientHello
            let client_hello = record_builder::build_client_hello_cbc();
            stream.write_all(&client_hello).await?;

            // Read ServerHello and handshake messages
            let mut buffer = vec![0u8; 8192];
            let bytes_read = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await??;

            if bytes_read == 0 {
                return Ok(ServerResponse {
                    connection_accepted: false,
                    alert_type: None,
                    response_time_ms: start_time.elapsed().as_secs_f64() * 1000.0,
                    shows_differential_behavior: false,
                });
            }

            // Send crafted malformed record based on type
            let malformed = record_builder::build_malformed_record(record_type);
            stream.write_all(&malformed).await?;

            // Try to read response
            let mut response = vec![0u8; 1024];
            let alert_type = match timeout(Duration::from_secs(2), stream.read(&mut response)).await
            {
                Ok(Ok(n)) if n > 0 => {
                    // Parse TLS alert if present
                    if response[0] == CONTENT_TYPE_ALERT && n >= 7 {
                        Some(response[6]) // Alert description
                    } else {
                        None
                    }
                }
                _ => None,
            };

            Ok(ServerResponse {
                connection_accepted: true,
                alert_type,
                response_time_ms: start_time.elapsed().as_secs_f64() * 1000.0,
                shows_differential_behavior: alert_type.is_some(),
            })
        }
        _ => Ok(ServerResponse {
            connection_accepted: false,
            alert_type: None,
            response_time_ms: start_time.elapsed().as_secs_f64() * 1000.0,
            shows_differential_behavior: false,
        }),
    }
}

/// Measure response time for a specific record type
pub(super) async fn measure_response_time(
    target: &Target,
    record_type: MalformedRecordType,
) -> Result<f64> {
    let response = send_malformed_record(target, record_type).await?;
    Ok(response.response_time_ms)
}
