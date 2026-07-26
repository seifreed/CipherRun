use crate::Result;
use tokio::io::AsyncReadExt;

pub(super) async fn read_complete_tls_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total_len = 5usize
        .checked_add(record_len)
        .ok_or_else(|| crate::TlsError::ParseError {
            message: "CCS TLS record length overflow".to_string(),
        })?;
    if total_len > buffer.len() {
        return Err(crate::TlsError::ParseError {
            message: "CCS TLS record length exceeds buffer".to_string(),
        });
    }

    buffer[..5].copy_from_slice(&header);
    stream.read_exact(&mut buffer[5..total_len]).await?;
    Ok(total_len)
}
