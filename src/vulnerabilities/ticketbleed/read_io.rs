use std::time::Duration;

use crate::constants::TLS_RECORD_HEADER_SIZE;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::session_ticket;

pub(super) async fn until_new_session_ticket(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
    per_read_timeout: Duration,
) -> usize {
    let mut total = 0usize;
    loop {
        if total >= buffer.len() {
            break;
        }
        let Some(read_buffer) = buffer.get_mut(total..) else {
            break;
        };
        let n = match timeout(per_read_timeout, stream.read(read_buffer)).await {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if n == 0 {
            break;
        }
        total += n;
        let Some(accumulated) = buffer.get(..total) else {
            break;
        };
        if let Ok(true) = session_ticket::is_present(accumulated) {
            break;
        }
    }
    total
}

pub(super) async fn complete_tls_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
    per_read_timeout: Duration,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        if total >= buffer.len() {
            break;
        }
        let Some(read_buffer) = buffer.get_mut(total..) else {
            break;
        };
        let n = match timeout(per_read_timeout, stream.read(read_buffer)).await {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if n == 0 {
            break;
        }
        total += n;
        if total >= TLS_RECORD_HEADER_SIZE {
            let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
            let record_total = TLS_RECORD_HEADER_SIZE
                .checked_add(record_len)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Ticketbleed TLS record length overflow",
                    )
                })?;
            if record_total > buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Ticketbleed TLS record length exceeds buffer",
                ));
            }
            if total >= record_total {
                break;
            }
        }
    }
    Ok(total)
}
