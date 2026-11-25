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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn record_buffer_has_room_for_the_largest_ssl_v2_record() {
        let buffer = record_buffer();

        assert_eq!(buffer.len(), SSLV2_MAX_RECORD_WITH_HEADER);
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn read_error_classification_distinguishes_empty_and_partial_reads() {
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
            assert!(is_empty_read_timeout(kind));
        }
        assert!(!is_empty_read_timeout(ErrorKind::UnexpectedEof));

        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::WouldBlock,
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
        ] {
            assert!(is_partial_read_end(kind));
        }
        assert!(!is_partial_read_end(ErrorKind::InvalidData));
    }

    async fn read_response(response: &'static [u8]) -> (usize, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buffer = [0; 8];
        let read = read_complete_sslv2_record(&mut stream, &mut buffer)
            .await
            .unwrap();
        server.await.unwrap();
        (read, buffer[..read].to_vec())
    }

    #[tokio::test]
    async fn complete_read_skips_tls_and_keeps_incomplete_sslv2_headers() {
        assert_eq!(
            read_response(&[0x16, 0x03, 0x01]).await,
            (3, vec![0x16, 0x03, 0x01])
        );
        assert_eq!(read_response(&[0x01, 0x00]).await, (2, vec![0x01, 0x00]));
    }

    #[tokio::test]
    async fn complete_read_stops_at_a_complete_sslv2_record() {
        assert_eq!(
            read_response(&[0x80, 0x01, 0x04]).await,
            (3, vec![0x80, 0x01, 0x04])
        );
    }
}
