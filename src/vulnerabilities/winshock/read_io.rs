use crate::constants::TLS_RECORD_HEADER_SIZE;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

pub(super) async fn complete_tls_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
    timeout_duration: Duration,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        if total >= buffer.len() {
            break;
        }
        let Some(read_buf) = buffer.get_mut(total..) else {
            break;
        };
        let n = match timeout(timeout_duration, stream.read(read_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        total += n;
        if total >= TLS_RECORD_HEADER_SIZE {
            let record_len = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
            let record_total = TLS_RECORD_HEADER_SIZE
                .checked_add(record_len)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Winshock TLS record length overflow",
                    )
                })?;
            if record_total > buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Winshock TLS record length exceeds buffer",
                ));
            }
            if total >= record_total {
                break;
            }
        }
    }
    Ok(total)
}
