// Shared TLS handshake read helper used by vulnerability probes.
//
// Large certificate chains and bundled ServerHello/Certificate/ServerKeyExchange
// messages routinely span multiple TLS records (and multiple TCP reads). A
// single `stream.read(..)` call therefore captures only a prefix of the server
// handshake, which skews timing measurements and truncates certificate parsing.
//
// `read_until_server_hello_done` mirrors the pattern already used by
// `src/vulnerabilities/robot.rs` and extends it to any vulnerability probe that
// needs the full handshake in the buffer before sending the attack record.

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Return true once a ServerHelloDone record (handshake type 0x0e) is present
/// anywhere in the buffer.
pub(super) fn has_server_hello_done(buf: &[u8]) -> bool {
    let mut offset = 0usize;
    while let Some(header_end) = offset.checked_add(5).filter(|&end| end <= buf.len()) {
        let record_header = &buf[offset..header_end];
        let content_type = record_header[0];
        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        // Slice lengths fit in isize; both wire lengths are strictly smaller than usize.
        let record_end = header_end + record_len;
        if record_end > buf.len() {
            break;
        }
        if content_type == 0x16 {
            let mut hs_start = header_end;
            while let Some(hs_header_end) = hs_start.checked_add(4).filter(|&end| end <= record_end)
            {
                let is_server_hello_done = buf.get(hs_start) == Some(&0x0e);
                let len_bytes = &buf[hs_start + 1..hs_header_end];
                let hs_len = ((len_bytes[0] as usize) << 16)
                    | ((len_bytes[1] as usize) << 8)
                    | len_bytes[2] as usize;
                let hs_end = hs_header_end + hs_len;
                if hs_end > record_end {
                    break;
                }
                if is_server_hello_done {
                    return true;
                }
                hs_start = hs_end;
            }
        }
        offset = record_end;
    }
    false
}

/// Read from `stream` into `buffer` until one of:
/// - A ServerHelloDone record is present in the accumulated bytes.
/// - The buffer fills up (prevents unbounded growth on adversarial servers).
/// - The per-read timeout elapses or the peer closes the connection.
///
/// Returns the number of bytes actually written into the buffer. Returns 0 if
/// the stream was closed or timed out before any data arrived.
pub(crate) async fn read_until_server_hello_done(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    per_read_timeout: Duration,
) -> usize {
    let mut total = 0usize;
    loop {
        if total >= buffer.len() {
            break;
        }
        let read_buffer = &mut buffer[total..];
        let n = match timeout(per_read_timeout, stream.read(read_buffer)).await {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if n == 0 {
            break;
        }
        total += n;
        let accumulated = &buffer[..total];
        if has_server_hello_done(accumulated) {
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Build a TLS handshake record (content type 0x16) containing a single
    /// handshake message of `handshake_type` with a given body.
    fn handshake_record(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(4 + body.len());
        msg.push(handshake_type);
        let len = body.len();
        msg.push(((len >> 16) & 0xff) as u8);
        msg.push(((len >> 8) & 0xff) as u8);
        msg.push((len & 0xff) as u8);
        msg.extend_from_slice(body);

        let mut record = Vec::with_capacity(5 + msg.len());
        record.push(0x16);
        record.push(0x03);
        record.push(0x03);
        record.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&msg);
        record
    }

    async fn stream_with_response(bytes: Vec<u8>) -> (TcpStream, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let client = TcpStream::connect(address)
            .await
            .expect("client should connect to loopback");
        let (mut server, _) = listener
            .accept()
            .await
            .expect("loopback connection should be accepted");
        let writer = tokio::spawn(async move {
            server
                .write_all(&bytes)
                .await
                .expect("response bytes should be written");
        });

        (client, writer)
    }

    #[test]
    fn detects_server_hello_done_across_records() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&handshake_record(0x02, &[0u8; 38])); // ServerHello
        buf.extend_from_slice(&handshake_record(0x0b, &[0u8; 64])); // Certificate
        buf.extend_from_slice(&handshake_record(0x0e, &[])); // ServerHelloDone
        assert!(has_server_hello_done(&buf));
    }

    #[test]
    fn detects_server_hello_done_inside_combined_record() {
        let mut messages = Vec::new();
        messages.extend_from_slice(&handshake_record(0x02, &[0u8; 38])[5..]);
        messages.extend_from_slice(&handshake_record(0x0e, &[])[5..]);

        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(messages.len() as u16).to_be_bytes());
        record.extend_from_slice(&messages);

        assert!(has_server_hello_done(&record));
    }

    #[test]
    fn returns_false_when_record_truncated() {
        let full = handshake_record(0x0e, &[]);
        // Slice short of the full record → not detected yet.
        assert!(!has_server_hello_done(
            full.get(..6)
                .expect("test record should have partial prefix")
        ));
    }

    #[test]
    fn ignores_non_handshake_records() {
        let mut record = handshake_record(0x0e, &[]);
        record[0] = 0x17;

        assert!(!has_server_hello_done(&record));
    }

    #[test]
    fn returns_false_when_server_hello_done_body_truncated() {
        let record = vec![
            0x16, 0x03, 0x03, 0x00, 0x04, // record length: handshake header only
            0x0e, 0x00, 0x00, 0x01, // ServerHelloDone declares one body byte
        ];
        assert!(!has_server_hello_done(&record));
    }

    #[test]
    fn returns_false_when_only_partial_records_present() {
        let incomplete = handshake_record(0x02, &[0u8; 38]);
        assert!(!has_server_hello_done(&incomplete));
    }

    #[tokio::test]
    async fn reads_until_server_hello_done_and_stops_at_full_buffer() {
        let response = handshake_record(0x0e, &[]);
        let (mut client, writer) = stream_with_response(response.clone()).await;
        let mut buffer = [0u8; 64];

        let bytes_read =
            read_until_server_hello_done(&mut client, &mut buffer, Duration::from_secs(1)).await;
        writer.await.expect("response writer should finish");

        assert_eq!(bytes_read, response.len());
        assert!(has_server_hello_done(&buffer[..bytes_read]));

        let incomplete_header = [0x16, 0x03, 0x03, 0x00, 0x64];
        let (mut client, writer) = stream_with_response(incomplete_header.to_vec()).await;
        let mut small_buffer = [0u8; 5];
        let bytes_read =
            read_until_server_hello_done(&mut client, &mut small_buffer, Duration::from_secs(1))
                .await;
        writer.await.expect("response writer should finish");
        assert_eq!(bytes_read, small_buffer.len());
    }

    #[tokio::test]
    async fn returns_partial_bytes_on_peer_close_and_zero_on_timeout() {
        let (mut client, writer) = stream_with_response(vec![0x16, 0x03]).await;
        let mut buffer = [0u8; 64];
        let bytes_read =
            read_until_server_hello_done(&mut client, &mut buffer, Duration::from_secs(1)).await;
        writer.await.expect("response writer should finish");
        assert_eq!(bytes_read, 2);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener should bind");
        let address = listener.local_addr().expect("listener address");
        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect to loopback");
        let server = tokio::spawn(async move {
            let (_connection, _) = listener.accept().await.expect("connection should arrive");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let bytes_read =
            read_until_server_hello_done(&mut client, &mut buffer, Duration::from_millis(1)).await;
        server.await.expect("loopback server should finish");
        assert_eq!(bytes_read, 0);
    }
}
