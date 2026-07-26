use super::sslv2;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

const SSLV2_MAX_RECORD_WITH_HEADER: usize = 32767 + 2;

pub(super) fn record_buffer() -> Vec<u8> {
    vec![0u8; SSLV2_MAX_RECORD_WITH_HEADER]
}

pub(super) async fn read_complete_sslv2_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buffer.len() {
        match timeout(Duration::from_secs(3), stream.read(&mut buffer[total..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total += n;
                if total >= 2 {
                    let Some((header_len, _record_len, record_total)) =
                        sslv2::record_shape(buffer.get(..total).unwrap_or(&[]))
                    else {
                        continue;
                    };
                    if total < header_len {
                        continue;
                    }
                    if record_total > buffer.len() {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "DROWN SSLv2 response length exceeds buffer",
                        ));
                    }
                    if total >= record_total {
                        break;
                    }
                }
            }
            Ok(Err(err)) if total == 0 && is_empty_read_timeout(err.kind()) => return Ok(0),
            Ok(Err(err)) if total > 0 && is_partial_read_end(err.kind()) => break,
            Ok(Err(err)) => return Err(err),
            Err(_) if total > 0 => break,
            Err(_) => return Ok(0),
        }
    }

    Ok(total)
}

fn is_empty_read_timeout(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

fn is_partial_read_end(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
    )
}
