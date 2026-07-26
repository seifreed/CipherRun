use std::time::Duration;

use crate::constants::TLS_RECORD_HEADER_SIZE;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub(super) async fn complete_tls_record(
    stream: &mut TcpStream,
    max_len: usize,
    read_timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut response = vec![0u8; max_len];
    let mut total = 0usize;
    loop {
        if total >= response.len() {
            break;
        }
        let read_buf = response.get_mut(total..).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "heartbeat response read offset exceeded buffer",
            )
        })?;
        let n = match timeout(read_timeout, stream.read(read_buf)).await {
            Ok(read) => read?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "heartbeat response read timed out",
                ));
            }
        };
        if n == 0 {
            break;
        }
        total += n;
        if total >= TLS_RECORD_HEADER_SIZE {
            let record_len = u16::from_be_bytes([response[3], response[4]]) as usize;
            let record_total = TLS_RECORD_HEADER_SIZE
                .checked_add(record_len)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "heartbeat response record length overflow",
                    )
                })?;
            if record_total > response.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "heartbeat response record length exceeds buffer",
                ));
            }
            if total >= record_total {
                break;
            }
        }
    }
    response.truncate(total);
    Ok(response)
}
