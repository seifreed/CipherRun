use crate::constants::TLS_RECORD_HEADER_SIZE;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

pub(super) async fn complete_tls_record(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    complete_tls_record_with_timeout(stream, buffer, Duration::from_secs(3)).await
}

async fn complete_tls_record_with_timeout(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    buffer: &mut [u8],
    read_timeout: Duration,
) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buffer.len() {
        match timeout(read_timeout, stream.read(&mut buffer[total..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total += n;
                if total >= TLS_RECORD_HEADER_SIZE {
                    let record_len = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
                    let record_total = TLS_RECORD_HEADER_SIZE + record_len;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, io, pin::Pin, task::Poll};
    use tokio::{
        io::{AsyncWriteExt, ReadBuf},
        net::TcpListener,
    };

    struct ScriptedReader(VecDeque<io::Result<Vec<u8>>>);

    impl tokio::io::AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
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

    fn scripted_reader(steps: impl IntoIterator<Item = io::Result<Vec<u8>>>) -> ScriptedReader {
        ScriptedReader(steps.into_iter().collect())
    }

    async fn connected_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        (
            client.expect("loopback connection should succeed"),
            accepted.expect("loopback listener should accept").0,
        )
    }

    #[tokio::test]
    async fn reads_a_complete_record_without_dropping_coalesced_bytes() {
        let (mut stream, mut peer) = connected_pair().await;
        peer.write_all(&[22, 3, 3, 0, 3, 1, 2, 3, 99, 99])
            .await
            .unwrap();
        let mut buffer = [0; 16];

        let length =
            complete_tls_record_with_timeout(&mut stream, &mut buffer, Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(length, 10);
        assert_eq!(&buffer[..length], &[22, 3, 3, 0, 3, 1, 2, 3, 99, 99]);
    }

    #[tokio::test]
    async fn returns_partial_bytes_when_peer_closes_early() {
        let (mut stream, mut peer) = connected_pair().await;
        peer.write_all(&[22, 3]).await.unwrap();
        drop(peer);
        let mut buffer = [0; 16];

        assert_eq!(
            complete_tls_record_with_timeout(&mut stream, &mut buffer, Duration::from_secs(1))
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn returns_zero_for_timeout_before_any_data() {
        let (mut stream, _peer) = connected_pair().await;
        let mut buffer = [0; 16];

        assert_eq!(
            complete_tls_record_with_timeout(&mut stream, &mut buffer, Duration::from_millis(1))
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn keeps_partial_bytes_on_timeout() {
        let (mut stream, mut peer) = connected_pair().await;
        peer.write_all(&[22, 3]).await.unwrap();
        let mut buffer = [0; 16];

        assert_eq!(
            complete_tls_record_with_timeout(&mut stream, &mut buffer, Duration::from_millis(1))
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn rejects_a_record_larger_than_the_buffer() {
        let (mut stream, mut peer) = connected_pair().await;
        peer.write_all(&[22, 3, 3, 0, 20]).await.unwrap();
        let mut buffer = [0; 10];

        let error =
            complete_tls_record_with_timeout(&mut stream, &mut buffer, Duration::from_secs(1))
                .await
                .expect_err("record must fit the buffer");

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn returns_zero_for_nonblocking_errors_before_data() {
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
            let mut reader = scripted_reader([Err(io::Error::from(kind))]);
            assert_eq!(
                complete_tls_record_with_timeout(
                    &mut reader,
                    &mut [0; 16],
                    Duration::from_secs(1),
                )
                .await
                .unwrap(),
                0
            );
        }
    }

    #[tokio::test]
    async fn returns_zero_when_reader_reaches_eof_without_data() {
        let mut reader = scripted_reader([]);
        assert_eq!(
            complete_tls_record_with_timeout(&mut reader, &mut [0; 16], Duration::from_secs(1),)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn returns_partial_data_for_recoverable_read_errors() {
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::WouldBlock,
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
        ] {
            let mut reader = scripted_reader([Ok(vec![22, 3]), Err(io::Error::from(kind))]);
            assert_eq!(
                complete_tls_record_with_timeout(
                    &mut reader,
                    &mut [0; 16],
                    Duration::from_secs(1),
                )
                .await
                .unwrap(),
                2
            );
        }
    }

    #[tokio::test]
    async fn propagates_unexpected_read_errors() {
        for steps in [
            vec![Err(io::Error::from(ErrorKind::PermissionDenied))],
            vec![
                Ok(vec![22, 3]),
                Err(io::Error::from(ErrorKind::PermissionDenied)),
            ],
        ] {
            let mut reader = scripted_reader(steps);
            let error =
                complete_tls_record_with_timeout(&mut reader, &mut [0; 16], Duration::from_secs(1))
                    .await
                    .expect_err("unexpected read errors must be returned");
            assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        }
    }
}
