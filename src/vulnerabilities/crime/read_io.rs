use crate::constants::TLS_RECORD_HEADER_SIZE;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

pub(super) async fn complete_tls_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buffer.len() {
        match timeout(Duration::from_secs(3), stream.read(&mut buffer[total..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total += n;
                if total >= TLS_RECORD_HEADER_SIZE {
                    let record_len = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
                    let record_total =
                        TLS_RECORD_HEADER_SIZE
                            .checked_add(record_len)
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    "CRIME TLS record length overflow",
                                )
                            })?;
                    if record_total > buffer.len() {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "CRIME TLS record length exceeds buffer",
                        ));
                    }
                    if total >= record_total {
                        break;
                    }
                }
            }
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
