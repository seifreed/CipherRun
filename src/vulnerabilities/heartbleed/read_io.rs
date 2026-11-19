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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (
            client.expect("loopback connection should succeed"),
            accepted.expect("loopback listener should accept").0,
        )
    }

    #[tokio::test]
    async fn reads_a_complete_tls_record() {
        let (mut client, mut peer) = connected_pair().await;
        let expected = [22, 3, 3, 0, 3, 1, 2, 3];
        peer.write_all(&expected).await.unwrap();

        assert_eq!(
            complete_tls_record(&mut client, 16, Duration::from_secs(1))
                .await
                .unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn returns_partial_data_when_peer_closes_before_a_full_header() {
        let (mut client, mut peer) = connected_pair().await;
        peer.write_all(&[22, 3]).await.unwrap();
        drop(peer);

        assert_eq!(
            complete_tls_record(&mut client, 16, Duration::from_secs(1))
                .await
                .unwrap(),
            [22, 3]
        );
    }

    #[tokio::test]
    async fn reports_read_timeout() {
        let (mut client, _peer) = connected_pair().await;

        let error = complete_tls_record(&mut client, 16, Duration::from_millis(1))
            .await
            .expect_err("idle peer should time out");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn rejects_record_larger_than_buffer() {
        let (mut client, mut peer) = connected_pair().await;
        peer.write_all(&[22, 3, 3, 0, 20]).await.unwrap();

        let error = complete_tls_record(&mut client, 10, Duration::from_secs(1))
            .await
            .expect_err("record must fit the buffer");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn zero_length_buffer_returns_without_reading() {
        let (mut client, _peer) = connected_pair().await;

        assert!(
            complete_tls_record(&mut client, 0, Duration::from_secs(1))
                .await
                .unwrap()
                .is_empty()
        );
    }
}
