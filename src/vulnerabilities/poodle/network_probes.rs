// Network probing for POODLE vulnerability detection
//
// Handles TLS connection establishment, sending malformed records,
// and capturing server responses for oracle analysis.

use crate::Result;
use crate::constants::{CONTENT_TYPE_ALERT, TLS_HANDSHAKE_TIMEOUT};
use crate::utils::network::Target;
use crate::utils::{VulnSslConfig, test_vuln_ssl_connection_outcome};
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
fn find_alert_description(response: &[u8], n: usize) -> Result<Option<u8>> {
    let response = response
        .get(..n)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "POODLE response read length exceeded buffer".to_string(),
        })?;
    let mut i = 0usize;
    while let Some(description_offset) = i.checked_add(6).filter(|&end| end < response.len()) {
        let Some(header_end) = i.checked_add(5) else {
            break;
        };
        let Some(header) = response
            .get(i..header_end)
            .and_then(|header| <&[u8; 5]>::try_from(header).ok())
        else {
            break;
        };
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] == CONTENT_TYPE_ALERT {
            if record_len != 2 {
                return Err(crate::TlsError::ParseError {
                    message: "Malformed TLS alert record length".to_string(),
                });
            }
            let Some(record_end) = header_end.checked_add(record_len) else {
                return Err(crate::TlsError::ParseError {
                    message: "TLS alert record length overflow".to_string(),
                });
            };
            if record_end > response.len() {
                return Err(crate::TlsError::ParseError {
                    message: "Truncated TLS alert record".to_string(),
                });
            }
            return Ok(response.get(description_offset).copied()); // level at i+5, description at i+6
        }
        let Some(next) = header_end.checked_add(record_len) else {
            break;
        };
        if next > response.len() {
            break;
        }
        i = next;
    }

    if response.first() == Some(&CONTENT_TYPE_ALERT) {
        return Err(crate::TlsError::ParseError {
            message: "Truncated TLS alert record".to_string(),
        });
    }

    Ok(None)
}

/// Check if server supports CBC cipher suites
pub(super) async fn supports_cbc_ciphers(
    target: &Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
) -> Result<Option<bool>> {
    const CBC_CIPHERS: &str = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA";
    test_vuln_ssl_connection_outcome(
        target,
        VulnSslConfig::with_ciphers(CBC_CIPHERS)
            .with_starttls(starttls)
            .with_starttls_server_mode(starttls_server_mode),
    )
    .await
}

/// Send a malformed TLS record for oracle detection
pub(super) async fn send_malformed_record(
    target: &Target,
    record_type: MalformedRecordType,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
) -> Result<ServerResponse> {
    let addr = target
        .socket_addrs()
        .first()
        .copied()
        .ok_or(crate::TlsError::NoSocketAddresses)?;
    match crate::utils::network::connect_with_starttls(
        addr,
        TLS_HANDSHAKE_TIMEOUT,
        starttls,
        &target.hostname,
        starttls_server_mode,
    )
    .await
    {
        Ok(mut stream) => {
            // Send ClientHello
            let client_hello = record_builder::build_client_hello_cbc()?;
            stream.write_all(&client_hello).await?;

            // V5 fix: read until ServerHelloDone. Previously a single `stream.read`
            // captured only the first TCP segment; large certificate chains
            // (RSA-4096 or multi-SAN certs) can span several records so the
            // malformed-record write happened while bytes were still in flight,
            // polluting the subsequent response-time measurement.
            let mut buffer = vec![0u8; 32768];
            let bytes_read = super::super::handshake_read::read_until_server_hello_done(
                &mut stream,
                &mut buffer,
                Duration::from_secs(3),
            )
            .await;

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

            // Try to read the full response so a fragmented alert record does
            // not get misclassified as absent.
            let mut response = vec![0u8; 1024];
            let bytes_read =
                super::PoodleTester::read_response_bytes(&mut stream, &mut response).await?;
            let alert_type = if bytes_read > 0 {
                find_alert_description(&response, bytes_read)?
            } else {
                None
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

impl<'a> super::PoodleTester<'a> {
    async fn read_response_bytes(
        stream: &mut tokio::net::TcpStream,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        use std::io::ErrorKind;

        let mut total = 0;
        while total < buffer.len() {
            match timeout(Duration::from_secs(2), stream.read(&mut buffer[total..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => total += n,
                Ok(Err(err))
                    if total == 0
                        && matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    return Ok(0);
                }
                Ok(Err(err))
                    if total > 0
                        && matches!(
                            err.kind(),
                            ErrorKind::TimedOut
                                | ErrorKind::WouldBlock
                                | ErrorKind::UnexpectedEof
                                | ErrorKind::ConnectionReset
                        ) =>
                {
                    break;
                }
                Ok(Err(err)) => return Err(err),
                Err(_) if total > 0 => break,
                Err(_) => return Ok(0),
            }
        }

        Ok(total)
    }
}

/// Measure response time for a specific record type
pub(super) async fn measure_response_time(
    target: &Target,
    record_type: MalformedRecordType,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
) -> Result<f64> {
    let response = send_malformed_record(target, record_type, starttls, starttls_server_mode).await?;
    Ok(response.response_time_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};

    #[test]
    fn test_find_alert_description_rejects_truncated_alert() {
        let response = [CONTENT_TYPE_ALERT, 0x03, 0x03, 0x00, 0x02, 0x02];
        let err = find_alert_description(&response, response.len())
            .expect_err("truncated alert should fail");
        assert!(err.to_string().contains("Truncated TLS alert record"));
    }

    #[test]
    fn test_find_alert_description_parses_alert() {
        let response = [CONTENT_TYPE_ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        assert_eq!(
            find_alert_description(&response, response.len()).expect("alert should parse"),
            Some(0x46)
        );
    }

    #[test]
    fn test_find_alert_description_rejects_malformed_length() {
        let response = [CONTENT_TYPE_ALERT, 0x03, 0x03, 0x00, 0x03, 0x02, 0x46];
        let err = find_alert_description(&response, response.len())
            .expect_err("malformed alert length should fail");
        assert!(
            err.to_string()
                .contains("Malformed TLS alert record length")
        );
    }

    #[test]
    fn test_find_alert_description_accepts_following_record() {
        let response = [
            CONTENT_TYPE_ALERT,
            0x03,
            0x03,
            0x00,
            0x02,
            0x02,
            0x46,
            0x16,
            0x03,
            0x03,
            0x00,
            0x00,
        ];
        assert_eq!(
            find_alert_description(&response, response.len()).expect("alert should parse"),
            Some(0x46)
        );
    }

    #[test]
    fn test_find_alert_description_skips_zero_length_record_before_alert() {
        let response = [
            0x16,
            0x03,
            0x03,
            0x00,
            0x00, // zero-length handshake record
            CONTENT_TYPE_ALERT,
            0x03,
            0x03,
            0x00,
            0x02,
            0x02,
            0x46,
        ];
        assert_eq!(
            find_alert_description(&response, response.len()).expect("alert should parse"),
            Some(0x46)
        );
    }

    #[tokio::test]
    async fn test_read_response_bytes_handles_fragmented_alert_record() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();
            let alert = [CONTENT_TYPE_ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
            let _ = socket.write_all(&alert[..3]).await;
            sleep(Duration::from_millis(50)).await;
            let _ = socket.write_all(&alert[3..]).await;
        });

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();

        let mut response = [0u8; 32];
        let n = super::super::PoodleTester::read_response_bytes(&mut stream, &mut response)
            .await
            .expect("read should succeed");
        assert_eq!(n, 7);
        assert_eq!(
            find_alert_description(&response, n).expect("alert should parse"),
            Some(0x46)
        );

        server.await.unwrap();
    }
}
