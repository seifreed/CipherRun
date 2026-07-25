use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_RECORD_HEADER_SIZE};
use tokio::io::AsyncReadExt;

pub(super) async fn read_tls_record(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; TLS_RECORD_HEADER_SIZE];
    if stream.read_exact(&mut header).await.is_err() {
        return Ok(None);
    }

    let Some(total_len) = total_len(&header)? else {
        return Ok(None);
    };
    let mut response = vec![0u8; total_len];
    response[..TLS_RECORD_HEADER_SIZE].copy_from_slice(&header);
    if stream
        .read_exact(&mut response[TLS_RECORD_HEADER_SIZE..])
        .await
        .is_err()
    {
        return Ok(None);
    }

    Ok(Some(response))
}

pub(super) fn total_len(header: &[u8; TLS_RECORD_HEADER_SIZE]) -> std::io::Result<Option<usize>> {
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = TLS_RECORD_HEADER_SIZE
        .checked_add(record_len)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLS record length overflow",
            )
        })?;
    if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
        return Ok(None);
    }
    Ok(Some(total_len))
}
