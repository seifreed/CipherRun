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

/// Scan a response buffer for a TLS Alert record and return the alert description byte.
///
/// After sending a malformed record, the response buffer may contain leftover handshake
/// messages from the previous read (e.g., tail of a certificate chain), so we cannot
/// assume the alert starts at offset 0.
fn find_alert_description(response: &[u8], n: usize) -> Option<u8> {
    let mut i = 0;
    while i + 7 <= n {
        let record_len = u16::from_be_bytes([response[i + 3], response[i + 4]]) as usize;
        if response[i] == CONTENT_TYPE_ALERT && record_len >= 2 {
            return Some(response[i + 6]); // level at i+5, description at i+6
        }
        let next = i + 5 + record_len;
        if record_len == 0 || next > n {
            break;
        }
        i = next;
    }
    None
}

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
        .ok_or(crate::TlsError::NoSocketAddresses)?;
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
                    response_time_ms: 0.0,
                    shows_differential_behavior: false,
                });
            }

            // Send crafted malformed record based on type — start timer here, after
            // TCP connect and TLS handshake overhead, so response_time_ms only measures
            // the server's reaction to the malformed record (relevant for Sleeping POODLE).
            let malformed = record_builder::build_malformed_record(record_type);
            let start_time = Instant::now();
            stream.write_all(&malformed).await?;

            // Try to read response
            let mut response = vec![0u8; 1024];
            let alert_type = match timeout(Duration::from_secs(2), stream.read(&mut response)).await
            {
                Ok(Ok(n)) if n > 0 => find_alert_description(&response, n),
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
            response_time_ms: 0.0,
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
