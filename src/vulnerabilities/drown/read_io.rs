use super::sslv2;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

const SSLV2_MAX_RECORD_WITH_HEADER: usize = 32767 + 2;

pub(super) fn record_buffer() -> Vec<u8> {
    vec![0u8; SSLV2_MAX_RECORD_WITH_HEADER]
}

pub(super) async fn read_complete_sslv2_record<R: AsyncRead + Unpin>(
    stream: &mut R,
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
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWriteExt;
    use tokio::io::ReadBuf;
    use tokio::net::TcpListener;

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

    struct PendingReader;

    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

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

    #[tokio::test]
    async fn complete_record_in_one_read_stops_without_waiting_for_more_data() {
        let mut reader = ScriptedReader(VecDeque::from([Ok(vec![0x80, 0x01, 0x04])]));
        let mut buffer = [0; 8];

        assert_eq!(
            read_complete_sslv2_record(&mut reader, &mut buffer)
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn incomplete_record_returns_partial_bytes_after_peer_eof() {
        let mut reader = ScriptedReader(VecDeque::from([Ok(vec![0x80, 0x03])]));
        let mut buffer = [0; 8];

        assert_eq!(
            read_complete_sslv2_record(&mut reader, &mut buffer)
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn oversized_record_is_rejected_before_buffer_overrun() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&[0x80, 0x02]).await.unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let error = read_complete_sslv2_record(&mut stream, &mut [0; 3])
            .await
            .expect_err("record larger than the supplied buffer must be rejected");

        assert_eq!(error.kind(), ErrorKind::InvalidData);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn empty_and_partial_reads_stop_after_the_read_timeout() {
        for (response, expected) in [(&[][..], 0), (&[0x80][..], 1)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
            let (close_tx, close_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                if !response.is_empty() {
                    stream.write_all(response).await.unwrap();
                }
                accepted_tx
                    .send(())
                    .expect("test should observe accepted peer");
                close_rx
                    .await
                    .expect("test should signal after the read timeout");
            });
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            accepted_rx
                .await
                .expect("test server should accept the probe connection");
            let read = read_complete_sslv2_record(&mut stream, &mut [0; 8])
                .await
                .unwrap();
            assert_eq!(read, expected);
            close_tx
                .send(())
                .expect("test server should still be waiting for the close signal");
            server.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_read_timeout_returns_zero_without_waiting_for_real_time() {
        let read = tokio::spawn(async {
            read_complete_sslv2_record(&mut PendingReader, &mut [0; 8]).await
        });

        tokio::time::advance(Duration::from_secs(3)).await;

        assert_eq!(read.await.unwrap().unwrap(), 0);
    }

    #[tokio::test]
    async fn read_errors_are_classified_by_whether_data_was_received() {
        let mut eof = ScriptedReader(VecDeque::new());
        assert_eq!(
            read_complete_sslv2_record(&mut eof, &mut [0; 8])
                .await
                .unwrap(),
            0
        );

        let mut empty_timeout =
            ScriptedReader(VecDeque::from([Err(io::Error::from(ErrorKind::TimedOut))]));
        assert_eq!(
            read_complete_sslv2_record(&mut empty_timeout, &mut [0; 8])
                .await
                .unwrap(),
            0
        );

        let mut partial_eof = ScriptedReader(VecDeque::from([
            Ok(vec![0x80]),
            Err(io::Error::from(ErrorKind::UnexpectedEof)),
        ]));
        assert_eq!(
            read_complete_sslv2_record(&mut partial_eof, &mut [0; 8])
                .await
                .unwrap(),
            1
        );

        let mut unexpected_error = ScriptedReader(VecDeque::from([Err(io::Error::from(
            ErrorKind::PermissionDenied,
        ))]));
        assert_eq!(
            read_complete_sslv2_record(&mut unexpected_error, &mut [0; 8])
                .await
                .expect_err("unexpected read errors should propagate")
                .kind(),
            ErrorKind::PermissionDenied
        );
    }
}
