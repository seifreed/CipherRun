use crate::constants::TLS_RECORD_HEADER_SIZE;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

pub(super) async fn complete_tls_record<R: AsyncRead + Unpin>(
    stream: &mut R,
    buffer: &mut [u8],
    timeout_duration: Duration,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        if total >= buffer.len() {
            break;
        }
        let n = match timeout(timeout_duration, stream.read(&mut buffer[total..])).await {
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
            let record_total = TLS_RECORD_HEADER_SIZE + record_len;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    struct ScriptedReader(VecDeque<io::Result<Vec<u8>>>);

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.0.pop_front() {
                Some(Ok(bytes)) => {
                    buffer.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                Some(Err(error)) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    #[tokio::test]
    async fn complete_record_reader_returns_eof_and_propagates_read_errors() {
        let mut eof = ScriptedReader(VecDeque::new());
        assert_eq!(
            complete_tls_record(&mut eof, &mut [0; 5], Duration::from_secs(1))
                .await
                .unwrap(),
            0
        );

        let mut partial = ScriptedReader(VecDeque::from([Ok(vec![0x16])]));
        assert_eq!(
            complete_tls_record(&mut partial, &mut [0; 5], Duration::from_secs(1))
                .await
                .unwrap(),
            1
        );

        let mut empty_buffer = ScriptedReader(VecDeque::new());
        assert_eq!(
            complete_tls_record(&mut empty_buffer, &mut [], Duration::from_secs(1))
                .await
                .unwrap(),
            0
        );

        let error = io::Error::from(io::ErrorKind::PermissionDenied);
        let mut failed = ScriptedReader(VecDeque::from([Err(error)]));
        assert_eq!(
            complete_tls_record(&mut failed, &mut [0; 5], Duration::from_secs(1))
                .await
                .expect_err("unexpected read errors should propagate")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn complete_record_reader_parses_header_and_rejects_oversized_record() {
        let mut complete = ScriptedReader(VecDeque::from([Ok(vec![
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00,
        ])]));
        assert_eq!(
            complete_tls_record(&mut complete, &mut [0; 6], Duration::from_secs(1))
                .await
                .expect("complete record should be read"),
            6
        );

        let mut oversized =
            ScriptedReader(VecDeque::from([Ok(vec![0x16, 0x03, 0x03, 0x00, 0x01])]));
        assert_eq!(
            complete_tls_record(&mut oversized, &mut [0; 5], Duration::from_secs(1))
                .await
                .expect_err("record larger than the buffer must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
